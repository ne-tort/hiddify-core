package connectip

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// H2 S2C (server→client) attribution counters for CONNECT-IP HTTP/2 DATAGRAM capsules.
// Cheap always-on atomics; RESULT_H2_S2C_STATS emission gated by MASQUE_CONNECT_IP_H2_ATTR=1.
var (
	h2S2CDatagramSentTotal  atomic.Uint64
	h2S2CDatagramBytesTotal atomic.Uint64
	h2S2CFlushTotal         atomic.Uint64
	h2S2CFlushNsTotal       atomic.Uint64
	h2S2CFlushSkipTotal     atomic.Uint64 // skipped Flush calls (NO_FLUSH or coalesce)
	h2S2CSinceFlush         atomic.Uint64 // datagrams since last Flush (coalesce probe)
	h2S2CAttrEmitterOnce sync.Once
	h2S2CLastFlushUnixNs atomic.Int64
)

func H2S2CDatagramSentTotal() uint64  { return h2S2CDatagramSentTotal.Load() }
func H2S2CDatagramBytesTotal() uint64 { return h2S2CDatagramBytesTotal.Load() }
func H2S2CFlushTotal() uint64         { return h2S2CFlushTotal.Load() }
func H2S2CFlushNsTotal() uint64       { return h2S2CFlushNsTotal.Load() }
func H2S2CFlushSkipTotal() uint64     { return h2S2CFlushSkipTotal.Load() }

// ResetH2S2CStats clears S2C attribution counters (tests / bench scrape windows).
func ResetH2S2CStats() {
	h2S2CDatagramSentTotal.Store(0)
	h2S2CDatagramBytesTotal.Store(0)
	h2S2CFlushTotal.Store(0)
	h2S2CFlushNsTotal.Store(0)
	h2S2CFlushSkipTotal.Store(0)
	h2S2CSinceFlush.Store(0)
	h2S2CLastFlushUnixNs.Store(0)
}

func h2S2CNoFlushEnabled() bool {
	v := os.Getenv("MASQUE_CONNECT_IP_H2_S2C_NO_FLUSH")
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

const (
	// Prod S2C coalesce (P0-1 VERIFIED FLUSH; P0-2 prod default).
	// Env MASQUE_CONNECT_IP_H2_S2C_FLUSH_EVERY / _IDLE_MS override for A/B/rollback.
	defaultH2S2CFlushEvery  = 16
	defaultH2S2CFlushIdleMs = 1
)

// h2S2CFlushEvery returns coalesce period for S2C DATAGRAM Flush.
// Prod default = 16 (P0-2). Env MASQUE_CONNECT_IP_H2_S2C_FLUSH_EVERY overrides;
// NO_FLUSH probe → 0. Env re-read for measure A/B.
func h2S2CFlushEvery() int {
	if h2S2CNoFlushEnabled() {
		return 0
	}
	v := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_H2_S2C_FLUSH_EVERY"))
	if v == "" {
		return defaultH2S2CFlushEvery
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return defaultH2S2CFlushEvery
	}
	return n
}

// h2S2CFlushIdleNs is max wait before forcing a Flush when coalesce (EVERY>1) is on.
// Keeps TCP handshake / sparse S2C alive while still batching under flood.
func h2S2CFlushIdleNs() int64 {
	v := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_H2_S2C_FLUSH_IDLE_MS"))
	if v == "" {
		return int64(defaultH2S2CFlushIdleMs) * int64(time.Millisecond)
	}
	ms, err := strconv.Atoi(v)
	if err != nil || ms < 0 {
		return int64(defaultH2S2CFlushIdleMs) * int64(time.Millisecond)
	}
	return int64(ms) * int64(time.Millisecond)
}

func h2S2CShouldFlushNow(every int, since uint64) bool {
	if every <= 1 {
		return true
	}
	if since%uint64(every) == 0 {
		return true
	}
	idle := h2S2CFlushIdleNs()
	if idle == 0 {
		return false
	}
	last := h2S2CLastFlushUnixNs.Load()
	if last == 0 {
		return true
	}
	return time.Now().UnixNano()-last >= idle
}

func h2S2CAttrEnabled() bool {
	v := os.Getenv("MASQUE_CONNECT_IP_H2_ATTR")
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

func h2S2CAttrFile() string {
	if p := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_H2_ATTR_FILE")); p != "" {
		return p
	}
	return "/tmp/masque-connect-ip-h2-s2c-stats.json"
}

type h2S2CStatsSnapshot struct {
	DatagramSent  uint64  `json:"datagram_sent"`
	DatagramBytes uint64  `json:"datagram_bytes"`
	FlushTotal    uint64  `json:"flush_total"`
	FlushNsTotal  uint64  `json:"flush_ns_total"`
	FlushSkip     uint64  `json:"flush_skip"`
	FlushNsPerPkt float64 `json:"flush_ns_per_pkt"`
	FlushEvery    int     `json:"flush_every"`
	PktsPerFlush  float64 `json:"pkts_per_flush"`
	NoFlushProbe  bool    `json:"no_flush_probe"`
}

func snapshotH2S2CStats() h2S2CStatsSnapshot {
	sent := h2S2CDatagramSentTotal.Load()
	flushN := h2S2CFlushTotal.Load()
	flushNs := h2S2CFlushNsTotal.Load()
	nsPer := 0.0
	if flushN > 0 {
		nsPer = float64(flushNs) / float64(flushN)
	}
	ppf := 0.0
	if flushN > 0 {
		ppf = float64(sent) / float64(flushN)
	}
	return h2S2CStatsSnapshot{
		DatagramSent:  sent,
		DatagramBytes: h2S2CDatagramBytesTotal.Load(),
		FlushTotal:    flushN,
		FlushNsTotal:  flushNs,
		FlushSkip:     h2S2CFlushSkipTotal.Load(),
		FlushNsPerPkt: nsPer,
		FlushEvery:    h2S2CFlushEvery(),
		PktsPerFlush:  ppf,
		NoFlushProbe:  h2S2CNoFlushEnabled(),
	}
}

func ensureH2S2CAttrEmitter() {
	if !h2S2CAttrEnabled() {
		return
	}
	h2S2CAttrEmitterOnce.Do(func() {
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			var lastLog time.Time
			for range t.C {
				snap := snapshotH2S2CStats()
				b, err := json.Marshal(snap)
				if err != nil {
					continue
				}
				_ = os.WriteFile(h2S2CAttrFile(), b, 0o644)
				// File is the scrape path; log at most ~0.2 Hz to avoid drowning docker bootstrap parsers.
				if time.Since(lastLog) >= 5*time.Second {
					log.Printf("RESULT_H2_S2C_STATS %s", b)
					lastLog = time.Now()
				}
			}
		}()
	})
}

// h2ServerCapsuleStream is CONNECT-IP on HTTP/2 (RFC 8441): capsules and RFC 9297 DATAGRAM
// payloads multiplex on one bidirectional CONNECT stream — request body peer→proxy, writes peer←proxy.
type h2ServerCapsuleStream struct {
	reqBody io.ReadCloser
	w       http.ResponseWriter
	mu      sync.Mutex
}

func (s *h2ServerCapsuleStream) Read(p []byte) (int, error) {
	if s.reqBody == nil {
		return 0, io.EOF
	}
	return s.reqBody.Read(p)
}

func (s *h2ServerCapsuleStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := writeAllWriter(s.w, p)
	// Control-capsule path keeps flush (probes apply only to SendDatagram / IP PDUs).
	flErr := flushHTTPResponseBody(s.w, false /*attribDatagram*/)
	if err != nil {
		return n, err
	}
	return n, flErr
}

func (s *h2ServerCapsuleStream) SendDatagram(payload []byte) error {
	ensureH2S2CAttrEmitter()
	var buf bytes.Buffer
	if err := http3.WriteCapsule(&buf, capsuleTypeHTTPDatagram, payload); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := writeAllWriter(s.w, buf.Bytes()); err != nil {
		return err
	}
	h2S2CDatagramSentTotal.Add(1)
	h2S2CDatagramBytesTotal.Add(uint64(len(payload)))
	every := h2S2CFlushEvery()
	if every == 0 {
		h2S2CFlushSkipTotal.Add(1)
		return nil
	}
	n := h2S2CSinceFlush.Add(1)
	if !h2S2CShouldFlushNow(every, n) {
		h2S2CFlushSkipTotal.Add(1)
		return nil
	}
	h2S2CSinceFlush.Store(0)
	err := flushHTTPResponseBody(s.w, true /*attribDatagram*/)
	h2S2CLastFlushUnixNs.Store(time.Now().UnixNano())
	return err
}

func (s *h2ServerCapsuleStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, errors.New("connect-ip: HTTP/2 capsule dataplane does not use stream ReceiveDatagram")
}

func (s *h2ServerCapsuleStream) CancelRead(quic.StreamErrorCode) {}

func (s *h2ServerCapsuleStream) Close() error {
	// readFromStream defers str.Close(); closing reqBody there aborts duplex CONNECT while
	// RoutePacketConnectionEx may still relay. Shutdown upload from Conn.Close instead.
	return nil
}

func (s *h2ServerCapsuleStream) closeMasqueH2RequestBody() error {
	if s.reqBody == nil {
		return nil
	}
	err := s.reqBody.Close()
	s.reqBody = nil
	return err
}

// flushHTTPResponseBody flushes the HTTP/2 response body. When attribDatagram is true,
// records flush count/ns for H2 S2C DATAGRAM attribution (P0-1).
func flushHTTPResponseBody(w http.ResponseWriter, attribDatagram bool) error {
	start := time.Now()
	rc := http.NewResponseController(w)
	err := rc.Flush()
	if attribDatagram {
		h2S2CFlushTotal.Add(1)
		h2S2CFlushNsTotal.Add(uint64(time.Since(start).Nanoseconds()))
	}
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	return nil
}

package connectip

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

// Single prod S2C flush policy for CONNECT-IP HTTP/2 DATAGRAM capsules:
// flush every h2S2CFlushEvery datagrams, or after h2S2CFlushIdle with no further
// SendDatagram (one-shot timer — not "idle check on next packet only").
const (
	h2S2CFlushEvery = 16
	h2S2CFlushIdle  = time.Millisecond
	// Mirror client hostKernelBulkEgressMinBytes: only large TCP DATA may skip Flush.
	h2S2CBulkMinBytes = 256
)

// Cheap always-on S2C counters (no env gates / alternate modes).
var (
	h2S2CDatagramSentTotal  atomic.Uint64
	h2S2CDatagramBytesTotal atomic.Uint64
	h2S2CFlushTotal         atomic.Uint64
	h2S2CFlushNsTotal       atomic.Uint64
	h2S2CFlushSkipTotal     atomic.Uint64
	h2S2CIdleFlushTotal     atomic.Uint64 // flushes from idle timer (P0-3b)
)

func H2S2CDatagramSentTotal() uint64  { return h2S2CDatagramSentTotal.Load() }
func H2S2CDatagramBytesTotal() uint64 { return h2S2CDatagramBytesTotal.Load() }
func H2S2CFlushTotal() uint64         { return h2S2CFlushTotal.Load() }
func H2S2CFlushNsTotal() uint64       { return h2S2CFlushNsTotal.Load() }
func H2S2CFlushSkipTotal() uint64     { return h2S2CFlushSkipTotal.Load() }
func H2S2CIdleFlushTotal() uint64     { return h2S2CIdleFlushTotal.Load() }

// ResetH2S2CStats clears S2C counters (tests).
func ResetH2S2CStats() {
	h2S2CDatagramSentTotal.Store(0)
	h2S2CDatagramBytesTotal.Store(0)
	h2S2CFlushTotal.Store(0)
	h2S2CFlushNsTotal.Store(0)
	h2S2CFlushSkipTotal.Store(0)
	h2S2CIdleFlushTotal.Store(0)
}

// h2ServerCapsuleStream is CONNECT-IP on HTTP/2 (RFC 8441): capsules and RFC 9297 DATAGRAM
// payloads multiplex on one bidirectional CONNECT stream — request body peer→proxy, writes peer←proxy.
type h2ServerCapsuleStream struct {
	reqBody io.ReadCloser
	w       http.ResponseWriter
	mu      sync.Mutex

	// Per-stream coalesce state (not package globals — multi-session safe).
	sinceFlush  uint64
	lastFlush   int64 // unix ns; 0 = never flushed datagrams on this stream
	idleTimer   *time.Timer
	pendingWire bytes.Buffer // P6-D1-H8: Fountain batch (NoWake path only)

	// maxDatagramPayload caps RFC9297 DATAGRAM capsule payload (ctxID||IP); 0 → h2DefaultMaxDatagramPayload.
	maxDatagramPayload int
}

func (s *h2ServerCapsuleStream) shouldFlushNowLocked() bool {
	if s.sinceFlush%uint64(h2S2CFlushEvery) == 0 {
		return true
	}
	if s.lastFlush == 0 {
		return true
	}
	return time.Now().UnixNano()-s.lastFlush >= int64(h2S2CFlushIdle)
}

// h2S2CIPv4TCPHasPayload mirrors connectip/frame.IPv4TCPHasPayload (no sing-box import here).
func h2S2CIPv4TCPHasPayload(pkt []byte) bool {
	const (
		ipv4Min = 20
		tcpMin  = 20
		tcpProto = 6
	)
	if len(pkt) < ipv4Min || pkt[0]>>4 != 4 || pkt[9] != tcpProto {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+tcpMin > len(pkt) {
		return false
	}
	doff := int(pkt[ihl+12]>>4) * 4
	if doff < tcpMin || ihl+doff > len(pkt) {
		return false
	}
	return len(pkt) > ihl+doff
}

// h2S2CImmediateFlushIP reports ACK/SYN/FIN/small/non-bulk: must Flush now so nested TCP
// upload clock is not delayed by EVERY=16 / 1ms idle (client C2S ACK-wake mirror).
func h2S2CImmediateFlushIP(ipPacket []byte) bool {
	return len(ipPacket) < h2S2CBulkMinBytes || !h2S2CIPv4TCPHasPayload(ipPacket)
}

func h2S2CImmediateFlushDatagramPayload(payload []byte) bool {
	_, n, err := quicvarint.Parse(payload)
	if err != nil || n <= 0 || n >= len(payload) {
		return true
	}
	return h2S2CImmediateFlushIP(payload[n:])
}

func (s *h2ServerCapsuleStream) stopIdleFlushLocked() {
	if s.idleTimer == nil {
		return
	}
	s.idleTimer.Stop()
	s.idleTimer = nil
}

// armIdleFlushLocked resets a one-shot idle flush. Call only while holding s.mu after a skip.
func (s *h2ServerCapsuleStream) armIdleFlushLocked() {
	s.stopIdleFlushLocked()
	s.idleTimer = time.AfterFunc(h2S2CFlushIdle, s.idleFlush)
}

func (s *h2ServerCapsuleStream) idleFlush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.idleTimer = nil
	if s.sinceFlush == 0 {
		return
	}
	h2S2CIdleFlushTotal.Add(1)
	_ = s.flushDatagramLocked()
}

func (s *h2ServerCapsuleStream) flushPendingWireLocked() error {
	if s.pendingWire.Len() == 0 {
		return nil
	}
	if _, err := writeAllWriter(s.w, s.pendingWire.Bytes()); err != nil {
		return err
	}
	s.pendingWire.Reset()
	h2S2CFlushTotal.Add(1)
	start := time.Now()
	err := flushHTTPResponseBody(s.w, false /*countDatagramFlush*/)
	h2S2CFlushNsTotal.Add(uint64(time.Since(start).Nanoseconds()))
	s.lastFlush = time.Now().UnixNano()
	return err
}

func (s *h2ServerCapsuleStream) flushDatagramLocked() error {
	s.stopIdleFlushLocked()
	s.sinceFlush = 0
	err := flushHTTPResponseBody(s.w, true /*countDatagramFlush*/)
	s.lastFlush = time.Now().UnixNano()
	return err
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
	// Control capsules always flush immediately (sparse / handshake-critical).
	flErr := flushHTTPResponseBody(s.w, false /*countDatagramFlush*/)
	if err != nil {
		return n, err
	}
	return n, flErr
}

func (s *h2ServerCapsuleStream) SendDatagram(payload []byte) error {
	if err := h2DatagramTooLarge(len(payload), s.maxDatagramPayload); err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := appendHTTPDatagramCapsule(&buf, payload); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := writeAllWriter(s.w, buf.Bytes()); err != nil {
		return err
	}
	h2S2CDatagramSentTotal.Add(1)
	h2S2CDatagramBytesTotal.Add(uint64(len(payload)))
	s.sinceFlush++
	if h2S2CImmediateFlushDatagramPayload(payload) || s.shouldFlushNowLocked() {
		return s.flushDatagramLocked()
	}
	h2S2CFlushSkipTotal.Add(1)
	s.armIdleFlushLocked()
	return nil
}

// SendProxiedIPDatagram implements proxiedIPDatagramSender; wake path matches SendDatagram
// (immediate write + EVERY/idle flush), without a middle compose alloc.
// ACK/small always Flush (nested TCP UP clock); bulk TCP DATA keeps EVERY/idle coalesce.
func (s *h2ServerCapsuleStream) SendProxiedIPDatagram(contextPrefix, ipPacket []byte) error {
	if err := h2DatagramTooLarge(len(contextPrefix)+len(ipPacket), s.maxDatagramPayload); err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := appendHTTPDatagramCapsuleParts(&buf, nil, contextPrefix, ipPacket); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := writeAllWriter(s.w, buf.Bytes()); err != nil {
		return err
	}
	h2S2CDatagramSentTotal.Add(1)
	h2S2CDatagramBytesTotal.Add(uint64(len(contextPrefix) + len(ipPacket)))
	s.sinceFlush++
	if h2S2CImmediateFlushIP(ipPacket) || s.shouldFlushNowLocked() {
		return s.flushDatagramLocked()
	}
	h2S2CFlushSkipTotal.Add(1)
	s.armIdleFlushLocked()
	return nil
}

// SendProxiedIPDatagramNoWake buffers RFC9297 wire for one forwarder download batch (Fountain).
// Does not retain ipPacket after return (copies into pendingWire).
func (s *h2ServerCapsuleStream) SendProxiedIPDatagramNoWake(contextPrefix, ipPacket []byte) error {
	if err := h2DatagramTooLarge(len(contextPrefix)+len(ipPacket), s.maxDatagramPayload); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := appendHTTPDatagramCapsuleParts(&s.pendingWire, nil, contextPrefix, ipPacket); err != nil {
		return err
	}
	h2S2CDatagramSentTotal.Add(1)
	h2S2CDatagramBytesTotal.Add(uint64(len(contextPrefix) + len(ipPacket)))
	return nil
}

// FlushProxiedIPDatagramSend flushes Fountain pending wire once per downloadCh batch.
func (s *h2ServerCapsuleStream) FlushProxiedIPDatagramSend() {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.flushPendingWireLocked()
}

func (s *h2ServerCapsuleStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, errors.New("connect-ip: HTTP/2 capsule dataplane does not use stream ReceiveDatagram")
}

func (s *h2ServerCapsuleStream) CancelRead(quic.StreamErrorCode) {}

func (s *h2ServerCapsuleStream) Close() error {
	// readFromStream defers str.Close(); closing reqBody there aborts duplex CONNECT while
	// RoutePacketConnectionEx may still relay. Shutdown upload from Conn.Close instead.
	s.mu.Lock()
	s.stopIdleFlushLocked()
	s.mu.Unlock()
	return nil
}

func (s *h2ServerCapsuleStream) closeMasqueH2RequestBody() error {
	s.mu.Lock()
	s.stopIdleFlushLocked()
	_ = s.flushPendingWireLocked()
	s.mu.Unlock()
	if s.reqBody == nil {
		return nil
	}
	err := s.reqBody.Close()
	s.reqBody = nil
	return err
}

// flushHTTPResponseBody flushes the HTTP/2 response body. When countDatagramFlush is true,
// records flush count/ns for S2C DATAGRAM counters.
func flushHTTPResponseBody(w http.ResponseWriter, countDatagramFlush bool) error {
	start := time.Now()
	if err := http.NewResponseController(w).Flush(); err == nil || errors.Is(err, http.ErrNotSupported) {
		if countDatagramFlush {
			h2S2CFlushTotal.Add(1)
			h2S2CFlushNsTotal.Add(uint64(time.Since(start).Nanoseconds()))
		}
		return nil
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	if countDatagramFlush {
		h2S2CFlushTotal.Add(1)
		h2S2CFlushNsTotal.Add(uint64(time.Since(start).Nanoseconds()))
	}
	return nil
}

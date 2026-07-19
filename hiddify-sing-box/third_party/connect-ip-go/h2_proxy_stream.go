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
	"github.com/quic-go/quic-go/http3"
)

// Single prod S2C flush policy for CONNECT-IP HTTP/2 DATAGRAM capsules:
// flush every h2S2CFlushEvery datagrams, or sooner if idle >= h2S2CFlushIdle.
const (
	h2S2CFlushEvery = 16
	h2S2CFlushIdle  = time.Millisecond
)

// Cheap always-on S2C counters (no env gates / alternate modes).
var (
	h2S2CDatagramSentTotal  atomic.Uint64
	h2S2CDatagramBytesTotal atomic.Uint64
	h2S2CFlushTotal         atomic.Uint64
	h2S2CFlushNsTotal       atomic.Uint64
	h2S2CFlushSkipTotal     atomic.Uint64
	h2S2CSinceFlush         atomic.Uint64
	h2S2CLastFlushUnixNs    atomic.Int64
)

func H2S2CDatagramSentTotal() uint64  { return h2S2CDatagramSentTotal.Load() }
func H2S2CDatagramBytesTotal() uint64 { return h2S2CDatagramBytesTotal.Load() }
func H2S2CFlushTotal() uint64         { return h2S2CFlushTotal.Load() }
func H2S2CFlushNsTotal() uint64       { return h2S2CFlushNsTotal.Load() }
func H2S2CFlushSkipTotal() uint64     { return h2S2CFlushSkipTotal.Load() }

// ResetH2S2CStats clears S2C counters (tests).
func ResetH2S2CStats() {
	h2S2CDatagramSentTotal.Store(0)
	h2S2CDatagramBytesTotal.Store(0)
	h2S2CFlushTotal.Store(0)
	h2S2CFlushNsTotal.Store(0)
	h2S2CFlushSkipTotal.Store(0)
	h2S2CSinceFlush.Store(0)
	h2S2CLastFlushUnixNs.Store(0)
}

func h2S2CShouldFlushNow(since uint64) bool {
	if since%uint64(h2S2CFlushEvery) == 0 {
		return true
	}
	last := h2S2CLastFlushUnixNs.Load()
	if last == 0 {
		return true
	}
	return time.Now().UnixNano()-last >= int64(h2S2CFlushIdle)
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
	// Control capsules always flush immediately (sparse / handshake-critical).
	flErr := flushHTTPResponseBody(s.w, false /*countDatagramFlush*/)
	if err != nil {
		return n, err
	}
	return n, flErr
}

func (s *h2ServerCapsuleStream) SendDatagram(payload []byte) error {
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
	n := h2S2CSinceFlush.Add(1)
	if !h2S2CShouldFlushNow(n) {
		h2S2CFlushSkipTotal.Add(1)
		return nil
	}
	h2S2CSinceFlush.Store(0)
	err := flushHTTPResponseBody(s.w, true /*countDatagramFlush*/)
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

// flushHTTPResponseBody flushes the HTTP/2 response body. When countDatagramFlush is true,
// records flush count/ns for S2C DATAGRAM counters.
func flushHTTPResponseBody(w http.ResponseWriter, countDatagramFlush bool) error {
	start := time.Now()
	rc := http.NewResponseController(w)
	err := rc.Flush()
	if countDatagramFlush {
		h2S2CFlushTotal.Add(1)
		h2S2CFlushNsTotal.Add(uint64(time.Since(start).Nanoseconds()))
	}
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	return nil
}

package connectip

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

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
	flErr := flushHTTPResponseBody(s.w)
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
	return flushHTTPResponseBody(s.w)
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

func flushHTTPResponseBody(w http.ResponseWriter) error {
	rc := http.NewResponseController(w)
	if err := rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	return nil
}

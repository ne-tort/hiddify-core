package masque

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type stubAddr string

func (a stubAddr) Network() string { return "udp" }
func (a stubAddr) String() string  { return string(a) }

type stubConn struct {
	readData      []byte
	readErr       error
	writeData     []byte
	writeErr      error
	closeErr      error
	closed        bool
	deadline      time.Time
	readDeadline  time.Time
	writeDeadline time.Time
	localAddr     net.Addr
	remoteAddr    net.Addr
}

func (s *stubConn) Read(p []byte) (int, error) {
	if s.readErr != nil {
		return 0, s.readErr
	}
	n := copy(p, s.readData)
	return n, nil
}

func (s *stubConn) Write(p []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	s.writeData = append([]byte(nil), p...)
	return len(p), nil
}

func (s *stubConn) Close() error {
	s.closed = true
	return s.closeErr
}

func (s *stubConn) LocalAddr() net.Addr {
	return s.localAddr
}

func (s *stubConn) RemoteAddr() net.Addr {
	return s.remoteAddr
}

func (s *stubConn) SetDeadline(t time.Time) error {
	s.deadline = t
	return nil
}

func (s *stubConn) SetReadDeadline(t time.Time) error {
	s.readDeadline = t
	return nil
}

func (s *stubConn) SetWriteDeadline(t time.Time) error {
	s.writeDeadline = t
	return nil
}

func TestConnectedPacketConnReadWriteAndDeadlines(t *testing.T) {
	remote := stubAddr("198.51.100.10:443")
	local := stubAddr("127.0.0.1:12345")
	base := &stubConn{
		readData:   []byte("ping"),
		localAddr:  local,
		remoteAddr: remote,
	}
	conn := &connectedPacketConn{Conn: base, remoteAddr: remote}

	readBuf := make([]byte, 16)
	n, addr, err := conn.ReadFrom(readBuf)
	if err != nil {
		t.Fatalf("read from connectedPacketConn: %v", err)
	}
	if got := string(readBuf[:n]); got != "ping" {
		t.Fatalf("unexpected read payload: %q", got)
	}
	if addr == nil || addr.String() != remote.String() {
		t.Fatalf("unexpected read addr: %v", addr)
	}

	written, err := conn.WriteTo([]byte("pong"), nil)
	if err != nil {
		t.Fatalf("write to connectedPacketConn: %v", err)
	}
	if written != 4 {
		t.Fatalf("unexpected write length: %d", written)
	}
	if got := string(base.writeData); got != "pong" {
		t.Fatalf("unexpected write payload: %q", got)
	}

	deadline := time.Now().Add(2 * time.Second)
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	if base.deadline.IsZero() || base.readDeadline.IsZero() || base.writeDeadline.IsZero() {
		t.Fatal("expected all deadline calls to be forwarded to underlying conn")
	}

	if got := conn.LocalAddr(); got == nil || got.String() != local.String() {
		t.Fatalf("unexpected local addr forwarding: %v", got)
	}
}

func TestConnectedPacketConnCloseHandlesEOFAndNil(t *testing.T) {
	conn := &connectedPacketConn{}
	if err := conn.Close(); err != nil {
		t.Fatalf("nil conn close must be no-op, got %v", err)
	}

	eofConn := &connectedPacketConn{Conn: &stubConn{closeErr: io.EOF}}
	if err := eofConn.Close(); err != nil {
		t.Fatalf("io.EOF must be normalized to success, got %v", err)
	}

	closeErr := errors.New("close failed")
	failConn := &connectedPacketConn{Conn: &stubConn{closeErr: closeErr}}
	err := failConn.Close()
	if !errors.Is(err, closeErr) {
		t.Fatalf("expected close error propagation, got %v", err)
	}
}

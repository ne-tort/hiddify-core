package h2

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type stubPacketConn struct {
	local     net.Addr
	remote    net.Addr
	writeN    atomic.Int32
	closed    atomic.Bool
}

func (s *stubPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (s *stubPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	s.writeN.Add(1)
	return len(p), nil
}
func (s *stubPacketConn) Close() error                     { s.closed.Store(true); return nil }
func (s *stubPacketConn) LocalAddr() net.Addr              { return s.local }
func (s *stubPacketConn) RemoteAddr() net.Addr             { return s.remote }
func (s *stubPacketConn) SetDeadline(time.Time) error      { return nil }
func (s *stubPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (s *stubPacketConn) SetWriteDeadline(time.Time) error { return nil }

// TestAsymmetricPacketConnSingleUploadSyncWrite verifies H3 prod shape: one upload leg → direct WriteTo, no worker pool.
func TestAsymmetricPacketConnSingleUploadSyncWrite(t *testing.T) {
	t.Parallel()
	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	download := &stubPacketConn{local: local, remote: local}
	upload := &stubPacketConn{local: local, remote: local}
	c := NewAsymmetricPacketConn(download, upload, local, local, nil)
	if strings.Contains(h2AsymmetricPacketConnSource, "uploadCh") {
		t.Fatal("asymmetric_packet_conn.go must not use async upload worker channel")
	}
	payload := []byte("sync-upload")
	if _, err := c.WriteTo(payload, local); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if got := upload.writeN.Load(); got != 1 {
		t.Fatalf("upload WriteTo calls=%d want 1 (direct, no worker)", got)
	}
	_ = c.Close()
}

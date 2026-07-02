package h2

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// slowUploadPacketConn blocks WriteTo until unblock is closed (simulates blocked H2 pipe).
type slowUploadPacketConn struct {
	net.PacketConn
	unblock   chan struct{}
	closeOnce sync.Once
	writes    atomic.Int32
	closed    atomic.Bool
	local     net.Addr
}

func (s *slowUploadPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	s.writes.Add(1)
	select {
	case <-s.unblock:
		if s.closed.Load() {
			return 0, net.ErrClosed
		}
		return len(p), nil
	case <-time.After(5 * time.Second):
		return 0, net.ErrClosed
	}
}

func (s *slowUploadPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, nil, io.EOF
}

func (s *slowUploadPacketConn) LocalAddr() net.Addr {
	if s.local != nil {
		return s.local
	}
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}

func (s *slowUploadPacketConn) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.unblock)
	})
	return nil
}

func newSlowUploadPacketConn() *slowUploadPacketConn {
	return &slowUploadPacketConn{unblock: make(chan struct{})}
}

func TestPacketConnCloseDuringBlockedUploadWrite(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		_ = pw.Close()
		_ = pr.Close()
	})
	c := NewPacketConn(PacketConnConfig{
		ReqBody: pw,
		Resp:    &http.Response{Body: io.NopCloser(bytes.NewReader(nil))},
	})

	payload := bytes.Repeat([]byte{'u'}, testUploadCoalesceThreshold)
	writeDone := make(chan error, 1)
	go func() {
		_, err := c.WriteTo(payload, nil)
		writeDone <- err
	}()

	time.Sleep(50 * time.Millisecond)
	closeDone := make(chan struct{})
	go func() {
		_ = c.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("PacketConn.Close blocked during upload")
	}

	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("expected error after Close during blocked upload")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WriteTo blocked after Close")
	}
}

func TestAsymmetricPacketConnCloseDuringBlockedUploadWrite(t *testing.T) {
	slowUpload := newSlowUploadPacketConn()
	download := newSlowUploadPacketConn()
	c := NewAsymmetricPacketConn(download, slowUpload, nil, nil, nil)

	payload := bytes.Repeat([]byte{'y'}, 512)
	writeDone := make(chan error, 1)
	go func() {
		_, err := c.WriteTo(payload, nil)
		writeDone <- err
	}()

	time.Sleep(50 * time.Millisecond)
	closeDone := make(chan struct{})
	go func() {
		_ = c.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("AsymmetricPacketConn.Close blocked during sync upload")
	}

	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("expected error after Close during blocked upload")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WriteTo blocked after Close")
	}
}

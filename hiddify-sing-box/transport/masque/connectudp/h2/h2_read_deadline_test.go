package h2

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// TestPacketConnReadDeadlineDoesNotCloseConn verifies read timeout does not tear down upload (C4 / G7).
func TestPacketConnReadDeadlineDoesNotCloseConn(t *testing.T) {
	bodyPr, bodyPw := io.Pipe()
	t.Cleanup(func() {
		_ = bodyPw.Close()
		_ = bodyPr.Close()
	})
	c := NewPacketConn(PacketConnConfig{
		ReqBody:    bodyPw,
		Resp:       &http.Response{Body: bodyPr},
		LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9},
	})
	t.Cleanup(func() { _ = c.Close() })

	if err := c.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _, err := c.ReadFrom(make([]byte, 512))
	if !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadFrom: %v want deadline exceeded", err)
	}
	if c.closed.Load() {
		t.Fatal("PacketConn closed on read deadline")
	}
	if _, werr := c.WriteTo(bytes.Repeat([]byte{'u'}, 64), c.RemoteAddr()); errors.Is(werr, net.ErrClosed) {
		t.Fatalf("WriteTo after read deadline: %v", werr)
	}
}

// TestAsymmetricPacketConnReadDeadlineSurvivesUploadWrite checks download read timeout
// does not close the asymmetric wrapper or upload legs.
func TestAsymmetricPacketConnReadDeadlineSurvivesUploadWrite(t *testing.T) {
	bodyPr, bodyPw := io.Pipe()
	t.Cleanup(func() {
		_ = bodyPw.Close()
		_ = bodyPr.Close()
	})
	download := NewPacketConn(PacketConnConfig{
		ReqBody:    bodyPw,
		Resp:       &http.Response{Body: bodyPr},
		LocalAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2},
		RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9},
	})
	upload := &stubUploadPacketConn{local: download.LocalAddr()}
	c := NewAsymmetricPacketConn(download, []net.PacketConn{upload}, download.LocalAddr(), download.RemoteAddr(), nil)
	t.Cleanup(func() { _ = c.Close() })

	if err := c.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _, err := c.ReadFrom(make([]byte, 512))
	if !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadFrom: %v want deadline exceeded", err)
	}
	if c.closed.Load() {
		t.Fatal("AsymmetricPacketConn closed on read deadline")
	}
	if download.closed.Load() {
		t.Fatal("download leg closed on read deadline")
	}
	if upload.closed.Load() {
		t.Fatal("upload leg closed on read deadline")
	}

	payload := bytes.Repeat([]byte{'y'}, 128)
	if _, werr := c.WriteTo(payload, c.RemoteAddr()); werr != nil {
		t.Fatalf("WriteTo after read deadline: %v", werr)
	}
}

// stubUploadPacketConn is a minimal upload leg that never blocks on WriteTo.
type stubUploadPacketConn struct {
	local  net.Addr
	closed atomic.Bool
}

func (s *stubUploadPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, io.EOF }
func (s *stubUploadPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	return len(p), nil
}
func (s *stubUploadPacketConn) Close() error {
	s.closed.Store(true)
	return nil
}
func (s *stubUploadPacketConn) LocalAddr() net.Addr  { return s.local }
func (s *stubUploadPacketConn) SetDeadline(time.Time) error      { return nil }
func (s *stubUploadPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (s *stubUploadPacketConn) SetWriteDeadline(time.Time) error { return nil }

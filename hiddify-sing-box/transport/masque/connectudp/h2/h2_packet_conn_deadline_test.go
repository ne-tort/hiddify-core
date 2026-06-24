package h2

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

// h2UDPTestPipeBody matches net/http.Response.Body (Read + Close) for an io.Pipe read half.
type h2UDPTestPipeBody struct{ *io.PipeReader }

func (b h2UDPTestPipeBody) Close() error { return b.PipeReader.Close() }

func TestPacketConnReadDeadlineElapsed(t *testing.T) {
	pr, _ := io.Pipe()
	t.Cleanup(func() { _ = pr.Close() })
	c := NewPacketConn(PacketConnConfig{
		Resp: &http.Response{Body: h2UDPTestPipeBody{pr}},
	})
	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _, err := c.ReadFrom(make([]byte, 64))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

func TestPacketConnReadDeadlineInterruptsBlockedBodyRead(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		_ = pw.Close()
		_ = pr.Close()
	})
	c := NewPacketConn(PacketConnConfig{
		Resp:       &http.Response{Body: h2UDPTestPipeBody{pr}},
		RemoteAddr: NewUDPAddr("192.0.2.99:5353"),
	})
	if err := c.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _, err := c.ReadFrom(make([]byte, 1024))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline exceeded after blocked read, got %v", err)
	}
	if c.IsClosed() {
		t.Fatal("PacketConn must stay open after read deadline (upload leg survives)")
	}
}

func TestPacketConnRejectsOversizedDatagramCapsule(t *testing.T) {
	oversizedInner := append([]byte{0}, bytes.Repeat([]byte{'y'}, h2c.MaxCapsulePayload())...)
	var wb bytes.Buffer
	if err := http3.WriteCapsule(&wb, http3.CapsuleType(h2c.CapsuleTypeDatagram), oversizedInner); err != nil {
		t.Fatal(err)
	}
	c := NewPacketConn(PacketConnConfig{
		Resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(wb.Bytes()))},
		RemoteAddr: NewUDPAddr("192.0.2.1:53"),
	})
	_, _, err := c.ReadFrom(make([]byte, h2c.MaxCapsulePayload()+128))
	if err == nil {
		t.Fatal("expected error for oversized DATAGRAM capsule")
	}
}

func TestPacketConnReadsBoundarySizedDatagramCapsule(t *testing.T) {
	udpPayload := bytes.Repeat([]byte{'z'}, h2c.MaxCapsulePayload()-1)
	inner := append([]byte{0}, udpPayload...)
	var wb bytes.Buffer
	if err := http3.WriteCapsule(&wb, http3.CapsuleType(h2c.CapsuleTypeDatagram), inner); err != nil {
		t.Fatal(err)
	}
	c := NewPacketConn(PacketConnConfig{
		Resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(wb.Bytes()))},
		RemoteAddr: NewUDPAddr("192.0.2.2:5353"),
	})
	dst := make([]byte, h2c.MaxCapsulePayload()+64)
	n, addr, err := c.ReadFrom(dst)
	if err != nil {
		t.Fatal(err)
	}
	if addr == nil || addr.String() == "" {
		t.Fatal("missing remote addr")
	}
	if n != len(udpPayload) {
		t.Fatalf("got n=%d want %d", n, len(udpPayload))
	}
}

func TestPacketConnWriteDeadlineElapsed(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		_ = pr.Close()
		_ = pw.Close()
	})
	c := NewPacketConn(PacketConnConfig{
		ReqBody: pw,
		Resp:    &http.Response{Body: io.NopCloser(bytes.NewReader(nil))},
	})
	if err := c.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := c.WriteTo([]byte{1, 2, 3}, nil)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

func TestPacketConnWriteDeadlineInterruptsBlockedBodyWrite(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		_ = pr.Close()
		_ = pw.Close()
	})
	c := NewPacketConn(PacketConnConfig{
		ReqBody: pw,
		Resp:    &http.Response{Body: io.NopCloser(bytes.NewReader(nil))},
	})
	if err := c.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := c.WriteTo(bytes.Repeat([]byte{'w'}, testUploadCoalesceThreshold), nil)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline exceeded after blocked write, got %v", err)
	}
	if !c.IsClosed() {
		t.Fatal("expected PacketConn closed after deadline interrupt teardown")
	}
}

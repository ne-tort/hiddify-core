package masque

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// h2UDPTestPipeBody matches net/http.Response.Body (Read + Close) for an io.Pipe read half.
type h2UDPTestPipeBody struct{ *io.PipeReader }

func (b h2UDPTestPipeBody) Close() error { return b.PipeReader.Close() }

func TestH2ConnectUDPPacketConnReadDeadlineElapsed(t *testing.T) {
	pr, _ := io.Pipe()
	t.Cleanup(func() { _ = pr.Close() })
	c := &h2ConnectUDPPacketConn{
		resp: &http.Response{Body: h2UDPTestPipeBody{pr}},
	}
	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _, err := c.ReadFrom(make([]byte, 64))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

// Regression: read deadline must unblock a blocked read on the CONNECT-UDP response body (parity with
// connect-ip ReadPacketWithContext), not only fire when checked between capsule loop iterations.
func TestH2ConnectUDPPacketConnReadDeadlineInterruptsBlockedBodyRead(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		_ = pw.Close()
		_ = pr.Close()
	})
	c := &h2ConnectUDPPacketConn{
		resp:       &http.Response{Body: h2UDPTestPipeBody{pr}},
		remoteAddr: masqueUDPAddr{s: "192.0.2.99:5353"},
	}
	_ = pw
	if err := c.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _, err := c.ReadFrom(make([]byte, 1024))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline exceeded after blocked read, got %v", err)
	}
	if !c.closed.Load() {
		t.Fatal("expected PacketConn closed after deadline interrupt teardown")
	}
}

func TestH2ConnectUDPPacketConnRejectsOversizedDatagramCapsule(t *testing.T) {
	t.Helper()
	oversizedInner := append([]byte{0}, bytes.Repeat([]byte{'y'}, h2ConnectUDPMaxCapsulePayload)...)
	var wb bytes.Buffer
	if err := http3.WriteCapsule(&wb, capsuleTypeDatagram, oversizedInner); err != nil {
		t.Fatal(err)
	}
	c := &h2ConnectUDPPacketConn{
		resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(wb.Bytes()))},
		remoteAddr: masqueUDPAddr{s: "192.0.2.1:53"},
	}
	_, _, err := c.ReadFrom(make([]byte, h2ConnectUDPMaxCapsulePayload+128))
	if err == nil {
		t.Fatal("expected error for oversized DATAGRAM capsule")
	}
}

func TestH2ConnectUDPPacketConnReadsBoundarySizedDatagramCapsule(t *testing.T) {
	t.Helper()
	udpPayload := bytes.Repeat([]byte{'z'}, h2ConnectUDPMaxCapsulePayload-1)
	inner := append([]byte{0}, udpPayload...)
	var wb bytes.Buffer
	if err := http3.WriteCapsule(&wb, capsuleTypeDatagram, inner); err != nil {
		t.Fatal(err)
	}
	c := &h2ConnectUDPPacketConn{
		resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(wb.Bytes()))},
		remoteAddr: masqueUDPAddr{s: "192.0.2.2:5353"},
	}
	dst := make([]byte, h2ConnectUDPMaxCapsulePayload+64)
	n, addr, err := c.ReadFrom(dst)
	if err != nil {
		t.Fatal(err)
	}
	if addr == nil || addr.String() == "" {
		t.Fatal("missing remote addr")
	}
	want := len(udpPayload)
	if n != want {
		t.Fatalf("got n=%d want %d", n, want)
	}
	for i := 0; i < n; i++ {
		if dst[i] != 'z' {
			t.Fatalf("byte %d: got %#x want 'z'", i, dst[i])
		}
	}
}

func TestH2ConnectUDPPacketConnWriteDeadlineElapsed(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		_ = pr.Close()
		_ = pw.Close()
	})
	c := &h2ConnectUDPPacketConn{
		reqBody: pw,
		resp:    &http.Response{Body: io.NopCloser(bytes.NewReader(nil))},
	}
	if err := c.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := c.WriteTo([]byte{1, 2, 3}, nil)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

// Regression: write deadline must unblock a blocked Write on the CONNECT-UDP request body (parity with
// ReadFrom / connect-ip), not only fire when checked before reqBody.Write.
func TestH2ConnectUDPPacketConnWriteDeadlineInterruptsBlockedBodyWrite(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		_ = pr.Close()
		_ = pw.Close()
	})
	c := &h2ConnectUDPPacketConn{
		reqBody: pw,
		resp:    &http.Response{Body: io.NopCloser(bytes.NewReader(nil))},
	}
	// Block the pipe: no reader draining pr.
	if err := c.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := c.WriteTo(bytes.Repeat([]byte{'w'}, 512), nil)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline exceeded after blocked write, got %v", err)
	}
	if !c.closed.Load() {
		t.Fatal("expected PacketConn closed after deadline interrupt teardown")
	}
}

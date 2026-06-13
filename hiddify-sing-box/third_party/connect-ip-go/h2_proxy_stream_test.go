package connectip

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
)

// TestH2ServerCapsuleStreamWriteFlushesOnce verifies each downlink Write flushes exactly once (G41 parity).
func TestH2ServerCapsuleStreamWriteFlushesOnce(t *testing.T) {
	t.Parallel()
	rec := &h2FlushCountResponseWriter{}
	str := &h2ServerCapsuleStream{w: rec}
	if _, err := str.Write([]byte("downlink-capsule")); err != nil {
		t.Fatal(err)
	}
	if got := rec.flushes.Load(); got != 1 {
		t.Fatalf("Write flushes=%d want 1", got)
	}
}

// TestH2ServerCapsuleStreamSendDatagramFlushesOnce verifies DATAGRAM capsule downlink flushes once per send.
func TestH2ServerCapsuleStreamSendDatagramFlushesOnce(t *testing.T) {
	t.Parallel()
	rec := &h2FlushCountResponseWriter{}
	str := &h2ServerCapsuleStream{w: rec}
	payload := append([]byte{0}, []byte("ip-pdu")...)
	if err := str.SendDatagram(payload); err != nil {
		t.Fatal(err)
	}
	if got := rec.flushes.Load(); got != 1 {
		t.Fatalf("SendDatagram flushes=%d want 1", got)
	}
}

// TestH2ServerCapsuleStreamReadUsesRequestBody verifies uplink capsules arrive via Extended CONNECT body.
func TestH2ServerCapsuleStreamReadUsesRequestBody(t *testing.T) {
	t.Parallel()
	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte("uplink-capsule"))
		_ = pw.Close()
	}()
	str := &h2ServerCapsuleStream{reqBody: pr, w: &h2FlushCountResponseWriter{}}
	buf := make([]byte, 32)
	n, err := str.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "uplink-capsule" {
		t.Fatalf("got %q want uplink-capsule", buf[:n])
	}
}

func TestH2ServerCapsuleStreamReceiveDatagramUnsupported(t *testing.T) {
	t.Parallel()
	str := &h2ServerCapsuleStream{}
	_, err := str.ReceiveDatagram(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestH2ServerCapsuleStreamCloseDoesNotCloseRequestBody(t *testing.T) {
	t.Parallel()
	body := &closeTrackingReadCloser{Reader: bytes.NewReader(nil)}
	str := &h2ServerCapsuleStream{reqBody: body, w: &h2FlushCountResponseWriter{}}
	if err := str.Close(); err != nil {
		t.Fatal(err)
	}
	if body.closeCalls != 0 {
		t.Fatal("Close must not close request body (RouteConnectIPBlocked may still relay)")
	}
}

type h2FlushCountResponseWriter struct {
	mu      sync.Mutex
	hdr     http.Header
	body    bytes.Buffer
	flushes atomic.Int32
}

func (w *h2FlushCountResponseWriter) Header() http.Header {
	if w.hdr == nil {
		w.hdr = make(http.Header)
	}
	return w.hdr
}

func (w *h2FlushCountResponseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.Write(p)
}

func (w *h2FlushCountResponseWriter) WriteHeader(int) {}

func (w *h2FlushCountResponseWriter) Flush() {
	w.flushes.Add(1)
}

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

// TestH2ServerCapsuleStreamSendDatagramFlushesOnce verifies first DATAGRAM flushes
// (idle path: lastFlush=0 forces flush even under prod EVERY=16).
func TestH2ServerCapsuleStreamSendDatagramFlushesOnce(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_H2_S2C_NO_FLUSH", "0")
	t.Setenv("MASQUE_CONNECT_IP_H2_S2C_FLUSH_EVERY", "")
	t.Setenv("MASQUE_CONNECT_IP_H2_S2C_FLUSH_IDLE_MS", "")
	ResetH2S2CStats()
	rec := &h2FlushCountResponseWriter{}
	str := &h2ServerCapsuleStream{w: rec}
	payload := append([]byte{0}, []byte("ip-pdu")...)
	if err := str.SendDatagram(payload); err != nil {
		t.Fatal(err)
	}
	if got := rec.flushes.Load(); got != 1 {
		t.Fatalf("SendDatagram flushes=%d want 1", got)
	}
	if got := H2S2CDatagramSentTotal(); got != 1 {
		t.Fatalf("datagram_sent=%d want 1", got)
	}
	if got := H2S2CFlushTotal(); got != 1 {
		t.Fatalf("flush_total=%d want 1", got)
	}
	// Mock Flush is near-instant; ns may be 0 on fast hosts — only require counter path ran.
	_ = H2S2CFlushNsTotal()
	if got := H2S2CDatagramBytesTotal(); got != uint64(len(payload)) {
		t.Fatalf("datagram_bytes=%d want %d", got, len(payload))
	}
	if got := h2S2CFlushEvery(); got != defaultH2S2CFlushEvery {
		t.Fatalf("prod default flush_every=%d want %d", got, defaultH2S2CFlushEvery)
	}
}

func TestH2ServerCapsuleStreamSendDatagramNoFlushProbe(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_H2_S2C_NO_FLUSH", "1")
	ResetH2S2CStats()
	rec := &h2FlushCountResponseWriter{}
	str := &h2ServerCapsuleStream{w: rec}
	payload := append([]byte{0}, []byte("ip-pdu")...)
	if err := str.SendDatagram(payload); err != nil {
		t.Fatal(err)
	}
	if got := rec.flushes.Load(); got != 0 {
		t.Fatalf("NO_FLUSH probe: flushes=%d want 0", got)
	}
	if got := H2S2CDatagramSentTotal(); got != 1 {
		t.Fatalf("datagram_sent=%d want 1", got)
	}
	if got := H2S2CFlushSkipTotal(); got != 1 {
		t.Fatalf("flush_skip=%d want 1", got)
	}
	if got := H2S2CFlushTotal(); got != 0 {
		t.Fatalf("flush_total=%d want 0 under NO_FLUSH", got)
	}
	// Control Write still flushes (probe is datagram-only).
	if _, err := str.Write([]byte("ctrl")); err != nil {
		t.Fatal(err)
	}
	if got := rec.flushes.Load(); got != 1 {
		t.Fatalf("Write flushes=%d want 1 (control path)", got)
	}
}

func TestH2ServerCapsuleStreamSendDatagramFlushEvery(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_H2_S2C_NO_FLUSH", "0")
	t.Setenv("MASQUE_CONNECT_IP_H2_S2C_FLUSH_EVERY", "4")
	t.Setenv("MASQUE_CONNECT_IP_H2_S2C_FLUSH_IDLE_MS", "0") // disable idle; pure count coalesce
	ResetH2S2CStats()
	rec := &h2FlushCountResponseWriter{}
	str := &h2ServerCapsuleStream{w: rec}
	payload := append([]byte{0}, []byte("ip-pdu")...)
	for i := 0; i < 4; i++ {
		if err := str.SendDatagram(payload); err != nil {
			t.Fatal(err)
		}
	}
	if got := rec.flushes.Load(); got != 1 {
		t.Fatalf("FLUSH_EVERY=4: flushes=%d want 1 after 4 datagrams", got)
	}
	if got := H2S2CDatagramSentTotal(); got != 4 {
		t.Fatalf("datagram_sent=%d want 4", got)
	}
	if got := H2S2CFlushTotal(); got != 1 {
		t.Fatalf("flush_total=%d want 1", got)
	}
	if got := H2S2CFlushSkipTotal(); got != 3 {
		t.Fatalf("flush_skip=%d want 3", got)
	}
}

func TestH2S2CFlushEveryProdDefault(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_H2_S2C_NO_FLUSH", "0")
	t.Setenv("MASQUE_CONNECT_IP_H2_S2C_FLUSH_EVERY", "")
	if got := h2S2CFlushEvery(); got != 16 {
		t.Fatalf("flush_every=%d want 16 prod default", got)
	}
	t.Setenv("MASQUE_CONNECT_IP_H2_S2C_FLUSH_EVERY", "1")
	if got := h2S2CFlushEvery(); got != 1 {
		t.Fatalf("flush_every override=%d want 1", got)
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

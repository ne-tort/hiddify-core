package connectip

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestH2ServerCapsuleStreamWriteFlushesOnce verifies each downlink Write flushes exactly once.
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

// TestH2ServerCapsuleStreamSendDatagramFirstFlushes: first PDU on a stream always flushes.
func TestH2ServerCapsuleStreamSendDatagramFirstFlushes(t *testing.T) {
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
	if got := H2S2CDatagramBytesTotal(); got != uint64(len(payload)) {
		t.Fatalf("datagram_bytes=%d want %d", got, len(payload))
	}
	_ = str.Close()
}

// TestH2ServerCapsuleStreamSendDatagramCoalesce: under flood (no idle gap), flush every 16.
func TestH2ServerCapsuleStreamSendDatagramCoalesce(t *testing.T) {
	ResetH2S2CStats()
	rec := &h2FlushCountResponseWriter{}
	str := &h2ServerCapsuleStream{w: rec}
	// Seed lastFlush so first PDU does not take the "never flushed" path.
	str.lastFlush = time.Now().UnixNano()
	payload := append([]byte{0}, []byte("ip-pdu")...)
	for i := 0; i < h2S2CFlushEvery; i++ {
		// Keep idle cold and cancel any armed idle timer so only every-N coalesce fires.
		str.mu.Lock()
		str.lastFlush = time.Now().UnixNano()
		str.stopIdleFlushLocked()
		str.mu.Unlock()
		if err := str.SendDatagram(payload); err != nil {
			t.Fatal(err)
		}
	}
	if got := rec.flushes.Load(); got != 1 {
		t.Fatalf("coalesce flushes=%d want 1 after %d datagrams", got, h2S2CFlushEvery)
	}
	if got := H2S2CDatagramSentTotal(); got != uint64(h2S2CFlushEvery) {
		t.Fatalf("datagram_sent=%d want %d", got, h2S2CFlushEvery)
	}
	if got := H2S2CFlushTotal(); got != 1 {
		t.Fatalf("flush_total=%d want 1", got)
	}
	if got := H2S2CFlushSkipTotal(); got != uint64(h2S2CFlushEvery-1) {
		t.Fatalf("flush_skip=%d want %d", got, h2S2CFlushEvery-1)
	}
	_ = str.Close()
}

// TestH2ServerCapsuleStreamIdleTimerFlushesSparse: skipped PDU flushes after idle without next send.
func TestH2ServerCapsuleStreamIdleTimerFlushesSparse(t *testing.T) {
	ResetH2S2CStats()
	rec := &h2FlushCountResponseWriter{}
	str := &h2ServerCapsuleStream{w: rec}
	str.lastFlush = time.Now().UnixNano()
	payload := append([]byte{0}, []byte("sparse")...)
	if err := str.SendDatagram(payload); err != nil {
		t.Fatal(err)
	}
	if got := rec.flushes.Load(); got != 0 {
		t.Fatalf("immediate flushes=%d want 0 (should coalesce+arm idle)", got)
	}
	if got := H2S2CFlushSkipTotal(); got != 1 {
		t.Fatalf("flush_skip=%d want 1", got)
	}
	deadline := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(deadline) {
		if rec.flushes.Load() >= 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got := rec.flushes.Load(); got != 1 {
		t.Fatalf("after idle flushes=%d want 1", got)
	}
	if got := H2S2CFlushTotal(); got != 1 {
		t.Fatalf("flush_total=%d want 1", got)
	}
	if got := H2S2CIdleFlushTotal(); got != 1 {
		t.Fatalf("idle_flush_total=%d want 1", got)
	}
	_ = str.Close()
}

// TestH2ServerCapsuleStreamFountainBatchFlush locks prod forwarder NoWake + one Flush per batch.
func TestH2ServerCapsuleStreamFountainBatchFlush(t *testing.T) {
	ResetH2S2CStats()
	rec := &h2FlushCountResponseWriter{}
	str := &h2ServerCapsuleStream{w: rec}
	ipPkt := bytes.Repeat([]byte("x"), 540)
	const batch = 32
	for i := 0; i < batch; i++ {
		if err := str.SendProxiedIPDatagramNoWake(contextIDZero, ipPkt); err != nil {
			t.Fatal(err)
		}
	}
	if got := rec.flushes.Load(); got != 0 {
		t.Fatalf("NoWake pending flushes=%d want 0 before FlushProxiedIPDatagramSend", got)
	}
	str.FlushProxiedIPDatagramSend()
	if got := rec.flushes.Load(); got != 1 {
		t.Fatalf("after FlushProxiedIPDatagramSend flushes=%d want 1", got)
	}
	if got := H2S2CDatagramSentTotal(); got != batch {
		t.Fatalf("datagram_sent=%d want %d", got, batch)
	}
	if got := H2S2CFlushTotal(); got != 1 {
		t.Fatalf("flush_total=%d want 1 (Fountain batch)", got)
	}
	_ = str.Close()
}

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

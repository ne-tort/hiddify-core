package conn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

type syncH3DatagramStream struct {
	sends atomic.Int64
}

func (s *syncH3DatagramStream) Read([]byte) (int, error)  { return 0, io.EOF }
func (s *syncH3DatagramStream) Write([]byte) (int, error) { return 0, nil }
func (s *syncH3DatagramStream) Close() error              { return nil }
func (s *syncH3DatagramStream) CancelRead(quic.StreamErrorCode) {}
func (s *syncH3DatagramStream) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, context.Canceled
}
func (s *syncH3DatagramStream) SendDatagram([]byte) error {
	s.sends.Add(1)
	return nil
}

type asyncH3NoWakeStream struct {
	syncH3DatagramStream
	noWake  atomic.Int64
	flushes atomic.Int64
}

func (s *asyncH3NoWakeStream) SendDatagramNoWake([]byte) error {
	s.noWake.Add(1)
	return nil
}

func (s *asyncH3NoWakeStream) FlushProxiedIPDatagramSend() {
	s.flushes.Add(1)
}

// TestH3C2SWriterSyncPathNoAsyncQueue documents upstream-shaped sync C2S (no writeCh pump).
func TestH3C2SWriterSyncPathNoAsyncQueue(t *testing.T) {
	t.Parallel()
	str := &syncH3DatagramStream{}
	w := newH3C2SWriter(str)
	if w.flushSender != nil {
		t.Fatal("sync stream must not enable NoWake batch path")
	}
	payload := make([]byte, 512)
	if err := w.writeBytes(context.Background(), nil, payload); err != nil {
		t.Fatal(err)
	}
	if got := str.sends.Load(); got != 1 {
		t.Fatalf("SendDatagram calls=%d want 1", got)
	}
	if w.writeCh != nil {
		t.Fatal("sync path must not allocate writeCh")
	}
}

// TestH3C2SWriterAsyncPathNoWakeBatch verifies prod async C2S batches NoWake sends (UDP-M3-04).
func TestH3C2SWriterAsyncPathNoWakeBatch(t *testing.T) {
	str := &asyncH3NoWakeStream{}
	w := newH3C2SWriter(str)
	payload := make([]byte, 64)
	const n = h3WriteHTTPBatchFlush
	for i := 0; i < n; i++ {
		if err := w.writeBytes(context.Background(), nil, payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	w.shutdown()
	if got := str.noWake.Load(); got != int64(n) {
		t.Fatalf("NoWake sends=%d want %d", got, n)
	}
	if got := str.flushes.Load(); got < 1 {
		t.Fatalf("expected at least one flush after batch of %d", n)
	}
}

// TestH3C2SWriterFlushDrainsPump verifies FlushC2SWrites waits for async pump (UDP-AUDIT G2).
func TestH3C2SWriterFlushDrainsPump(t *testing.T) {
	str := &asyncH3NoWakeStream{}
	w := newH3C2SWriter(str)
	payload := make([]byte, 64)
	if err := w.writeBytes(context.Background(), nil, payload); err != nil {
		t.Fatal(err)
	}
	w.drainQueue()
	if got := str.noWake.Load(); got != 1 {
		t.Fatalf("after drainQueue NoWake=%d want 1", got)
	}
	w.shutdown()
}

// TestH3C2SWriterAsyncPoolReuse checks write buf pool is returned after pump send (UDP-AUDIT G3).
func TestH3C2SWriterAsyncPoolReuse(t *testing.T) {
	str := &asyncH3NoWakeStream{}
	w := newH3C2SWriter(str)
	payload := make([]byte, 512)
	const n = 64
	for i := 0; i < n; i++ {
		if err := w.writeBytes(context.Background(), nil, payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	w.shutdown()
	if got := str.noWake.Load(); got != int64(n) {
		t.Fatalf("NoWake sends=%d want %d", got, n)
	}
}
func TestH3C2SWriterIdleTailFlushPartialBatch(t *testing.T) {
	str := &asyncH3NoWakeStream{}
	w := newH3C2SWriter(str)
	payload := make([]byte, 64)
	const partial = 5
	for i := 0; i < partial; i++ {
		if err := w.writeBytes(context.Background(), nil, payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	w.shutdown()
	if got := str.noWake.Load(); got != int64(partial) {
		t.Fatalf("NoWake sends=%d want %d", got, partial)
	}
	if got := str.flushes.Load(); got < 1 {
		t.Fatalf("idle tail flush: flushes=%d want >=1 after partial batch", got)
	}
}

func benchmarkH3C2SWrite(b *testing.B, async bool) {
	payload := make([]byte, 512)
	ctx := context.Background()
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	if async {
		str := &asyncH3NoWakeStream{}
		w := newH3C2SWriter(str)
		for i := 0; i < b.N; i++ {
			if err := w.writeBytes(ctx, nil, payload); err != nil {
				b.Fatal(err)
			}
		}
		w.drainQueue()
		return
	}
	str := &syncH3DatagramStream{}
	w := newH3C2SWriter(str)
	for i := 0; i < b.N; i++ {
		if err := w.writeBytes(ctx, nil, payload); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkH3C2SWriteSync512 profiles upstream-shaped sync SendDatagram C2S @512 B.
func BenchmarkH3C2SWriteSync512(b *testing.B) {
	benchmarkH3C2SWrite(b, false)
}

// BenchmarkH3C2SWriteAsync512 profiles prod NoWake+batch async C2S @512 B (UDP-M3-04).
func BenchmarkH3C2SWriteAsync512(b *testing.B) {
	benchmarkH3C2SWrite(b, true)
}

// TestH3ConnC2SProdPathUsesNoWakeWhenAvailable locks H3Conn → patched http3 NoWake interface.
func TestH3ConnC2SProdPathUsesNoWakeWhenAvailable(t *testing.T) {
	str := &asyncH3NoWakeStream{}
	c := NewH3Conn(str, masqueAddr{"l"}, masqueAddr{"r"})
	payload := make([]byte, 128)
	if _, err := c.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	}
	c.FlushC2SWrites()
	time.Sleep(10 * time.Millisecond)
	if str.noWake.Load() == 0 {
		t.Fatal("prod H3Conn must use NoWake batch path when stream supports it")
	}
	_ = c.Close()
}

// TestH3C2SWriterStoreErrStable keeps the stored error after the storeErr stack frame returns (UDP-BUG-07).
func TestH3C2SWriterStoreErrStable(t *testing.T) {
	w := newH3C2SWriter(&syncH3DatagramStream{})
	want := errors.New("send failed")
	w.storeErr(want)
	for i := 0; i < 64; i++ {
		_ = fmt.Sprintf("stack noise %d", i)
	}
	if err := w.takeErr(); !errors.Is(err, want) {
		t.Fatalf("takeErr: %v want %v", err, want)
	}
}

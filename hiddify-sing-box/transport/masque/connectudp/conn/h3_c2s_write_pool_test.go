package conn

import (
	"context"
	"sync/atomic"
	"testing"
)

// TestH3C2SWriterReleasesBufOnClosedBeforeEnqueue verifies CL2 pool return on closed abort.
func TestH3C2SWriterReleasesBufOnClosedBeforeEnqueue(t *testing.T) {
	t.Parallel()
	str := &asyncH3NoWakeStream{}
	w := newH3C2SWriter(str, 0)
	w.start()
	var closed atomic.Bool
	closed.Store(true)
	payload := make([]byte, 512)
	const storm = 512
	for i := 0; i < storm; i++ {
		if err := w.writeBytes(context.Background(), &closed, payload); err == nil {
			t.Fatal("want error when conn closed before enqueue")
		}
	}
	closed.Store(false)
	if err := w.writeBytes(context.Background(), &closed, payload); err != nil {
		t.Fatalf("write after closed storm: %v", err)
	}
	w.shutdown()
	if str.noWake.Load() != 1 {
		t.Fatalf("NoWake sends=%d want 1 after reopen", str.noWake.Load())
	}
}

// TestH3C2SWriterReleasesBufOnCanceledEnqueue verifies pool return when ctx canceled before enqueue.
func TestH3C2SWriterReleasesBufOnCanceledEnqueue(t *testing.T) {
	t.Parallel()
	str := &asyncH3NoWakeStream{}
	w := newH3C2SWriter(str, 0)
	w.start()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	payload := make([]byte, 128)
	const storm = 256
	for i := 0; i < storm; i++ {
		_ = w.writeBytes(ctx, nil, payload)
	}
	if err := w.writeBytes(context.Background(), nil, payload); err != nil {
		t.Fatalf("write after cancel storm: %v", err)
	}
	w.shutdown()
}

package relay

import (
	"context"
	"testing"
	"time"
)

// TestH3C2SOnwardFlushCoalescesBacklog: when TryReceive drains a backlog, onward
// writes must WriteBatch up to h3C2SOnwardFlushChunk (not one syscall per packet).
// Local Docker ≥500 Mbit/s previously overflowed http3 stream_datagram_queue because
// FlushChunk=1 forced single Writes despite a ready kernel WriteBatch path.
func TestH3C2SOnwardFlushCoalescesBacklog(t *testing.T) {
	const n = 300 // > SendBatchMax so we exercise multi-chunk flush
	str := &scriptedC2SStream{wake: make(chan struct{}, 8)}
	for i := 0; i < n; i++ {
		str.enqueue(ctx0Datagram(byte(i)))
	}
	str.closeEOF()

	w := &countingBatchWriter{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := proxyConnSendWith(ctx, str, w); err != nil {
		t.Fatalf("proxyConnSendWith: %v", err)
	}
	if w.writes != n {
		t.Fatalf("payloads written=%d want %d", w.writes, n)
	}
	// With FlushChunk=SendBatchMax, 300 packets → ≤3 batch calls (128+128+44).
	// FlushChunk=1 would yield ~300 calls.
	maxCalls := (n + h3C2SOnwardFlushChunk - 1) / h3C2SOnwardFlushChunk
	if w.batchCalls > maxCalls {
		t.Fatalf("batchCalls=%d want ≤%d (FlushChunk=%d); drain is not coalescing",
			w.batchCalls, maxCalls, h3C2SOnwardFlushChunk)
	}
	if w.maxBatch < 2 {
		t.Fatalf("maxBatch=%d: expected coalesced WriteBatch sizes ≥2 under backlog", w.maxBatch)
	}
	if w.maxBatch > h3C2SOnwardFlushChunk {
		t.Fatalf("maxBatch=%d > FlushChunk=%d", w.maxBatch, h3C2SOnwardFlushChunk)
	}
	t.Logf("RESULT_H3_C2S_FLUSH_COALESCE n=%d batchCalls=%d maxBatch=%d flushChunk=%d",
		n, w.batchCalls, w.maxBatch, h3C2SOnwardFlushChunk)
}

// TestH3C2SOnwardFlushChunkMatchesBatchMax locks the prod constant that enables WriteBatch.
func TestH3C2SOnwardFlushChunkMatchesBatchMax(t *testing.T) {
	if h3C2SOnwardFlushChunk != h3C2SUDPSendBatchMax {
		t.Fatalf("h3C2SOnwardFlushChunk=%d want %d (must match SendBatchMax for WriteBatch)",
			h3C2SOnwardFlushChunk, h3C2SUDPSendBatchMax)
	}
	if h3C2SOnwardFlushChunk < 32 {
		t.Fatalf("h3C2SOnwardFlushChunk=%d too small for high-PPS C2S drain", h3C2SOnwardFlushChunk)
	}
}

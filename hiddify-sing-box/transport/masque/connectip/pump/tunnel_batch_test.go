package pump

import (
	"context"
	"sync"
	"testing"
	"time"
)

type batchMockDevice struct {
	mu      sync.Mutex
	batches [][]byte
	written [][]byte
}

func (d *batchMockDevice) ReadEgressBatch(_ context.Context, slots []EgressSlot, maxN int) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for n < maxN && len(d.batches) > 0 {
		pkt := d.batches[0]
		d.batches = d.batches[1:]
		if len(slots[n].Buf) < len(pkt) {
			break
		}
		copy(slots[n].Buf, pkt)
		slots[n].Len = len(pkt)
		n++
	}
	return n, nil
}

func (d *batchMockDevice) ReadPacket(context.Context, []byte) (int, error) {
	return 0, nil
}

func (d *batchMockDevice) WritePacket(pkt []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.written = append(d.written, append([]byte(nil), pkt...))
	return nil
}

func (d *batchMockDevice) Close() error { return nil }

func TestRunTunnelBatchMultiPktPerIter(t *testing.T) {
	dev := &batchMockDevice{
		batches: [][]byte{
			{1, 2, 3}, {4, 5, 6}, {7, 8, 9}, {10, 11, 12},
			{1, 2, 3}, {4, 5, 6},
		},
	}
	conn := newMockPacketConn()
	flushes := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = RunTunnelBatch(ctx, dev, conn, TunnelOptions{
			MTU:         DefaultTunnelMTU,
			OnLoopInEnd: func() { flushes++ },
		}, 2)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond)

	conn.mu.Lock()
	writes := len(conn.written)
	conn.mu.Unlock()
	if writes < 4 {
		t.Fatalf("writes=%d want >=4", writes)
	}
	if flushes < 2 {
		t.Fatalf("flushes=%d want >=2 (one per batch iter)", flushes)
	}
	ratio := float64(writes) / float64(flushes)
	if ratio < 1.8 {
		t.Fatalf("pkts/flush=%.2f want >=1.8", ratio)
	}
}

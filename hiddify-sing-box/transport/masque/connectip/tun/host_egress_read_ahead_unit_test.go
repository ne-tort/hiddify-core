package tun

import (
	"context"
	"testing"
	"time"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

func TestHostEgressReadAheadDequeueBeforeExpiredCtx(t *testing.T) {
	t.Parallel()
	pkt := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00}
	feed := make(chan []byte, 2)
	feed <- pkt
	feed <- pkt
	inner := func(ctx context.Context, dst []byte) (int, error) {
		select {
		case p := <-feed:
			return copy(dst, p), nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, batch := WrapHostEgressReadAheadBatch(ctx, inner)
	time.Sleep(15 * time.Millisecond)

	bufs := [][]byte{make([]byte, 1500), make([]byte, 1500)}
	got, err := batch.ReadBatch(context.Background(), bufs, 1)
	if err != nil || got != 1 {
		t.Fatalf("first read: got=%d err=%v", got, err)
	}
	got2, err := batch.ReadBatch(cippump.LoopInExpiredDrainCtx(), bufs[1:], 1)
	if err != nil || got2 != 1 {
		t.Fatalf("drain read: got=%d err=%v want 1 pkt from queue", got2, err)
	}
}

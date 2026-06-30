package connectip

import (
	"sync/atomic"
	"testing"

	cipnet "github.com/sagernet/sing-box/transport/masque/connectip/netstack"
)

type recordingPacketDest struct {
	writes atomic.Int64
}

func (d *recordingPacketDest) WritePacket([]byte) ([]byte, error) {
	d.writes.Add(1)
	return nil, nil
}

func (d *recordingPacketDest) ReadPacket([]byte) (int, error) { return 0, nil }
func (d *recordingPacketDest) Close() error                   { return nil }

// TestBatchingPipeProxiedStreamDeferredFlushLocalize verifies batched NoWake without Flush
// stalls egress (native connect_ip deferred wake regression before egress poke fix).
func TestBatchingPipeProxiedStreamDeferredFlushLocalize(t *testing.T) {
	dest := &recordingPacketDest{}
	stream := &batchingPipeProxiedStream{dest: dest}

	const n = 64
	pkt := cipnet.BorrowOutboundPayload(20)
	pkt[0] = 0x45
	pkt[8] = 64
	for i := 0; i < n; i++ {
		dup := cipnet.BorrowOutboundPayload(20)
		copy(dup, pkt)
		if err := stream.SendProxiedIPDatagramNoWake(nil, dup); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	if got := dest.writes.Load(); got != 0 {
		t.Fatalf("deferred: dest writes=%d want 0 before flush", got)
	}
	stream.FlushProxiedIPDatagramSend()
	if got := dest.writes.Load(); int(got) != n {
		t.Fatalf("after flush: dest writes=%d want %d", got, n)
	}
	cipnet.ReturnOutboundBuf(pkt)
}

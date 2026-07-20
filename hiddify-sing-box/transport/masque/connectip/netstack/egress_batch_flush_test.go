package netstack

import (
	"testing"

	cipframe "github.com/sagernet/sing-box/transport/masque/connectip/frame"
)

// P6-B2: coalesced ACK must be recoverable after a full batch without relying on queue-empty path.
func TestP6B2EgressBatchFlushAllAcksAfterCap(t *testing.T) {
	t.Parallel()
	b := newEgressBatch()
	pkt := make([]byte, 40)
	flow := cipframe.TCP4Flow{
		Src:     [4]byte{198, 18, 0, 1},
		Dst:     [4]byte{127, 0, 0, 1},
		SrcPort: 12345,
		DstPort: 80,
	}
	b.pendingAck[flow] = pkt
	out := b.flushAllAcks()
	if len(out) != 1 || out[0] == nil {
		t.Fatalf("flushAllAcks len=%d want 1 non-nil", len(out))
	}
	if len(b.pendingAck) != 0 {
		t.Fatalf("pendingAck residual=%d", len(b.pendingAck))
	}
}

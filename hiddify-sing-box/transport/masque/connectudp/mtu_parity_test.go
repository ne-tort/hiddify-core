package connectudp

import (
	"testing"

	"github.com/sagernet/sing-box/option"
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	h3c "github.com/sagernet/sing-box/transport/masque/h3"
)

// TestConnectUDPMTUCeilingParityH2H3 documents intentional H2↔H3 CONNECT-UDP MTU behavior:
// H3 QUIC HTTP DATAGRAM clamps at ceiling−slack (~1380 B @ 1500); oversize app payloads split
// in DatagramSplitConn. H2 RFC 9297 capsules split at MaxUDPPayloadPerDatagramCapsule
// (ceiling+slack−1); masque-go H3 path drops/rejects >1500 on wire, H2 never needs drop.
func TestDatagramSplitMTUCeilingParityH2H3(t *testing.T) {
	ceiling := cip.DatagramCeilingMax()

	h3Max := h3c.UDPWriteMax(ceiling, 65535)
	if h3Max != ceiling-h3c.UDPDatagramWriteSlack {
		t.Fatalf("H3 UDPWriteMax=%d want ceiling-slack=%d", h3Max, ceiling-h3c.UDPDatagramWriteSlack)
	}
	if h3Max >= ceiling {
		t.Fatalf("H3 write max %d must stay below datagram ceiling %d", h3Max, ceiling)
	}

	h2Step := h2c.MaxUDPPayloadPerDatagramCapsule()
	if h2Step != cip.H2MaxCapsulePayload(ceiling)-1 {
		t.Fatalf("H2 per-capsule UDP max=%d want H2MaxCapsulePayload-1=%d",
			h2Step, cip.H2MaxCapsulePayload(ceiling)-1)
	}
	if h2Step <= h3Max {
		t.Fatalf("H2 capsule chunk %d must exceed H3 datagram max %d (H2 uses slack on wire)", h2Step, h3Max)
	}

	oversize := ceiling + 100
	h3Chunks := h3c.SplitPayloadSizes(oversize, h3Max)
	if len(h3Chunks) < 2 {
		t.Fatalf("H3 split oversize payload: got %v want >=2 chunks", h3Chunks)
	}
	for _, n := range h3Chunks {
		if n > h3Max {
			t.Fatalf("H3 chunk %d exceeds max %d", n, h3Max)
		}
	}

	// DatagramSplitConn H2 path caps tunnel chunk to h2Step even when caller passes higher max.
	st := &stubPacketConn{failAfterNWrites: -1}
	c := newSplitConn(st, h2Step+500, option.MasqueHTTPLayerH2)
	payload := make([]byte, h2Step+h2Step)
	if _, err := c.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	}
	if got := st.writeLens; len(got) != 2 || got[0] != h2Step || got[1] != h2Step {
		t.Fatalf("H2 split writes=%v want two %d-byte chunks", got, h2Step)
	}
}

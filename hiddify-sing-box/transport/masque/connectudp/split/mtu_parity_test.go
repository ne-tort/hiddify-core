package split

import (
	"testing"

	"github.com/sagernet/sing-box/option"
	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	h3c "github.com/sagernet/sing-box/transport/masque/h3"
)

// TestDatagramSplitMTUCeilingParityH2H3 documents H2↔H3 CONNECT-UDP MTU ceilings and
// RFC 9298 §5 reject-on-oversize (no multi-datagram invent).
func TestDatagramSplitMTUCeilingParityH2H3(t *testing.T) {
	ceiling := cudprelay.ProdRelayMaxUDPPayloadBytes

	h3Max := h3c.UDPWriteMax(ceiling, 65535)
	if h3Max != ceiling-h3c.UDPDatagramWriteSlack {
		t.Fatalf("H3 UDPWriteMax=%d want ceiling-slack=%d", h3Max, ceiling-h3c.UDPDatagramWriteSlack)
	}
	if h3Max >= ceiling {
		t.Fatalf("H3 write max %d must stay below datagram ceiling %d", h3Max, ceiling)
	}

	h2Step := h2c.MaxUDPPayloadPerDatagramCapsule()
	if h2Step <= h3Max {
		t.Fatalf("H2 capsule max %d must exceed H3 datagram max %d (H2 uses slack on wire)", h2Step, h3Max)
	}

	// DatagramSplitConn rejects oversize instead of chunking (F-H3-SPLIT-01 / F-H2-SPLIT-01).
	st := &stubPacketConn{failAfterNWrites: -1}
	c := newSplitConn(st, h2Step+500, option.MasqueHTTPLayerH2)
	payload := make([]byte, h2Step+1)
	n, err := c.WriteTo(payload, nil)
	if err == nil {
		t.Fatal("expected oversize reject on H2 path")
	}
	if n != 0 || len(st.writeLens) != 0 {
		t.Fatalf("n=%d writes=%v want reject with no writes", n, st.writeLens)
	}

	st2 := &stubPacketConn{failAfterNWrites: -1}
	c3 := newSplitConn(st2, h3Max, option.MasqueHTTPLayerH3)
	n, err = c3.WriteTo(make([]byte, h3Max+1), nil)
	if err == nil {
		t.Fatal("expected oversize reject on H3 path")
	}
	if n != 0 || len(st2.writeLens) != 0 {
		t.Fatalf("H3 n=%d writes=%v want reject with no writes", n, st2.writeLens)
	}
}

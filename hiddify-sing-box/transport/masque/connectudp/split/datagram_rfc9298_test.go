package split

import (
	"testing"

	cudpframe "github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	h3c "github.com/sagernet/sing-box/transport/masque/h3"
)

// TestDatagramSplitConnRejectsOversizeRFC9298 ensures oversize app payloads are rejected
// (RFC 9298 §5: one UDP = one HTTP Datagram), not chunked below the tunnel max.
func TestDatagramSplitConnRejectsOversizeRFC9298(t *testing.T) {
	t.Parallel()
	st := &stubPacketConn{failAfterNWrites: -1}
	max := h3c.UDPWriteMax(1500, 65535)
	c := newSplitConn(st, max, "")
	payload := make([]byte, max+1)
	n, err := c.WriteTo(payload, nil)
	if err == nil {
		t.Fatal("expected oversize reject")
	}
	if n != 0 {
		t.Fatalf("n=%d want 0", n)
	}
	if len(st.writeLens) != 0 {
		t.Fatalf("writes=%v want none", st.writeLens)
	}
	if max > cudpframe.MaxProxiedUDPPayloadBytes {
		t.Fatalf("tunnel max %d exceeds RFC %d", max, cudpframe.MaxProxiedUDPPayloadBytes)
	}
}

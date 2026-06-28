package split

import (
	"testing"

	cudpframe "github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	h3c "github.com/sagernet/sing-box/transport/masque/h3"
)

// TestDatagramSplitConnTunnelChunksBelowRFC9298Max ensures each inner datagram stays within RFC 9298 §4.
func TestDatagramSplitConnTunnelChunksBelowRFC9298Max(t *testing.T) {
	t.Parallel()
	st := &stubPacketConn{failAfterNWrites: -1}
	max := h3c.UDPWriteMax(1500, 65535)
	c := newSplitConn(st, max, "")
	payload := make([]byte, max*3+100)
	if _, err := c.WriteTo(payload, nil); err != nil {
		t.Fatal(err)
	}
	for i, n := range st.writeLens {
		if n > cudpframe.MaxProxiedUDPPayloadBytes {
			t.Fatalf("chunk %d len=%d exceeds RFC 9298 max %d", i, n, cudpframe.MaxProxiedUDPPayloadBytes)
		}
		if n > max {
			t.Fatalf("chunk %d len=%d exceeds tunnel max %d", i, n, max)
		}
	}
}

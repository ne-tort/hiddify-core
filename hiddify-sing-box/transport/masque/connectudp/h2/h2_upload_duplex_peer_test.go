package h2

import "testing"

// TestUploadLegIgnoresDuplexPeerActive locks H2-1: asymmetric upload stays thin (no echo coalesce).
func TestUploadLegIgnoresDuplexPeerActive(t *testing.T) {
	t.Parallel()
	up := NewPacketConn(PacketConnConfig{UploadOnly: true, LegProfile: LegProfileUpload})
	up.markDuplexPeerActive()
	if up.duplexActive.Load() {
		t.Fatal("LegProfileUpload upload leg must not arm duplexActive from peer activity")
	}
}

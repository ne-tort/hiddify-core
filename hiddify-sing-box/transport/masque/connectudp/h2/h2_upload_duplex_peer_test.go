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

func TestEchoBidiArmsDuplexPeerActive(t *testing.T) {
	t.Parallel()
	bidi := NewPacketConn(PacketConnConfig{LegProfile: LegProfileEchoBidi})
	bidi.markDuplexPeerActive()
	if !bidi.duplexActive.Load() {
		t.Fatal("echo bidi leg should arm duplexActive on peer activity")
	}
}

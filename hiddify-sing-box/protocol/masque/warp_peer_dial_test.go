package masque

import "testing"

func TestWarpMasqueDialPeerAndTLSUsesPeerIPv4AndSNIFromHostname(t *testing.T) {
	peer, tls := warpMasqueDialPeerAndTLS(
		"engage.cloudflareclient.com",
		"162.159.192.9:0", "",
		"",
	)
	if peer != "162.159.192.9" {
		t.Fatalf("quic peer override: got %q want %q", peer, "162.159.192.9")
	}
	if tls != "engage.cloudflareclient.com" {
		t.Fatalf("tls SNI: got %q want %q", tls, "engage.cloudflareclient.com")
	}
}

func TestWarpMasqueDialPeerAndTLSMasqueServerOverrideSkipsPeerIP(t *testing.T) {
	peer, tls := warpMasqueDialPeerAndTLS(
		"engage.cloudflareclient.com",
		"162.159.192.9:0", "",
		"custom.example",
	)
	if peer != "" {
		t.Fatalf("expected empty quic_peer when masque server set, got %q", peer)
	}
	if tls != "" {
		t.Fatalf("expected empty tls override for explicit server, got %q", tls)
	}
}

func TestWarpMasqueDialPeerAndTLSNoPinReturnsEmpty(t *testing.T) {
	peer, tls := warpMasqueDialPeerAndTLS("engage.cloudflareclient.com", "", "", "")
	if peer != "" || tls != "" {
		t.Fatalf("want empty quic_peer/sni for logical-only path, got peer=%q tls=%q", peer, tls)
	}
}

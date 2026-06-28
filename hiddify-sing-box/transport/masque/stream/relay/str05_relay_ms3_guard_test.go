package relay

import (
	"strings"
	"testing"
)

// TestSTR05ProdRelayBidiWakerUsesHTTP3MS3 locks server CONNECT-stream relay wake via http3 MS3 hooks (DIP-2).
func TestSTR05ProdRelayBidiWakerUsesHTTP3MS3(t *testing.T) {
	t.Parallel()
	for _, needle := range []string{
		"WakeMasqueRelayAfterDownloadWrite",
		"WakeMasqueRelayAfterUploadRead",
		"ArmMasqueBidiDuplexParallel",
		"IsMasqueBidiDuplexUploadStarted",
	} {
		if !strings.Contains(relayBidiWakerAuditSource, needle) {
			t.Fatalf("relay_bidi_waker.go must expose MS3 relay hook %q", needle)
		}
	}
	for _, forbidden := range []string{
		"SendDatagram",
		"MasqueWakeConnSend",
		"ReceiveDatagram",
	} {
		if strings.Contains(relayBidiWakerAuditSource, forbidden) {
			t.Fatalf("relay_bidi_waker.go must not reference datagram-plane hook %q", forbidden)
		}
	}
}

// TestSTR05ProdRelayUsesBidiStreamPath locks H3 CONNECT-stream server relay uses relayTCPTunnelBidiStream shape.
func TestSTR05ProdRelayUsesBidiStreamPath(t *testing.T) {
	t.Parallel()
	bundle := relayGoAuditBundle()
	if !strings.Contains(bundle, "relayTCPTunnelBidiStream") {
		t.Fatal("stream/relay must keep relayTCPTunnelBidiStream for saturated duplex")
	}
	if !strings.Contains(bundle, "relayBidiWakerFrom") {
		t.Fatal("stream/relay must route bidi wake through relayBidiWakerFrom* helpers")
	}
}

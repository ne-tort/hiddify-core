package relay

import (
	"strings"
	"testing"
)

// TestRelayTunnelBidiH2oThinWireLock: H3 bidi relay uses plain io.CopyBuffer (h2o 64 KiB parity).
func TestRelayTunnelBidiH2oThinWireLock(t *testing.T) {
	t.Parallel()
	bundle := relayGoAuditBundle()
	idxFn := strings.Index(bundle, "func relayTCPTunnelBidiStream")
	if idxFn < 0 {
		t.Fatal("relay missing relayTCPTunnelBidiStream")
	}
	section := bundle[idxFn:]
	for _, needle := range []string{
		"EnableMasqueConnectStream",
		"relayTunnelCopyBufferH3Upload(targetConn, uploadSrc)",
		"relayTunnelDownloadRelayH3(bidi, targetConn)",
		"relayTunnelPrimeDownload(src)",
		"io.CopyBuffer",
	} {
		if !strings.Contains(section, needle) && !strings.Contains(bundle, needle) {
			t.Fatalf("relay H3 thin path missing anchor %q", needle)
		}
	}
	for _, forbidden := range []string{
		"armDuplexParallel",
		"ArmMasqueBidiDuplexParallel",
		"RelayDuplexArmUploadBytes",
	} {
		if strings.Contains(bundle, forbidden) {
			t.Fatalf("relay must not reference MS3 duplex hook %q", forbidden)
		}
	}
}

// TestRelayHijackReleaseRequestBody: CONNECT hijack must release req.Body after HTTPStream takeover.
func TestRelayHijackReleaseRequestBody(t *testing.T) {
	t.Parallel()
	bundle := relayGoAuditBundle()
	for _, needle := range []string{
		"releaseConnectRelayRequestBody(reqBody)",
		"ReleaseHTTPStream()",
	} {
		if !strings.Contains(bundle, needle) {
			t.Fatalf("relay missing hijack release anchor %q", needle)
		}
	}
}

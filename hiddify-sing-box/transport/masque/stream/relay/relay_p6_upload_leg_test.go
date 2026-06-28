package relay

import (
	"strings"
	"testing"
)

// TestRelayP6UploadLegWireLock (H3-L1c-6): P6 upload CONNECT server relay probes upload leg,
// arms duplex after bulk threshold, and uses H3 bidi upload copy — not legacy reqbody path.
func TestRelayP6UploadLegWireLock(t *testing.T) {
	t.Parallel()
	bundle := relayGoAuditBundle()
	for _, needle := range []string{
		"relayH3ProbeUploadLeg",
		"relayH3UploadLegDownloadPrimary",
		"prepareDownloadPrimary",
		"PrepareMasqueRelayDownloadPrimary",
		"relayTunnelCopyBufferH3BidiUpload",
	} {
		if !strings.Contains(bundle, needle) {
			t.Fatalf("relay.go missing H3-L1c-6 anchor %q", needle)
		}
	}
	if !strings.Contains(bundle, "legRole string") {
		t.Fatal("relay.go missing legRole parameter on RelayTCPTunnel")
	}
	for _, needle := range []string{
		"relayTunnelCopyBufferH2BidiUpload",
		"relayTunnelWakeH2AfterUploadRead",
	} {
		if !strings.Contains(relayH2AuditSource, needle) {
			t.Fatalf("relay_bidi_boost.go missing H2 relay anchor %q", needle)
		}
	}
}


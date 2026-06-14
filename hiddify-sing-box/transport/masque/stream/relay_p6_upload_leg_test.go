package stream

import (
	_ "embed"
	"strings"
	"testing"
)

// TestRelayP6UploadLegWireLock (H3-L1c-6): P6 upload CONNECT server relay must discard target
// download and use upload-boost wake — not pump bulk S2C on the upload QUIC conn.
func TestRelayP6UploadLegWireLock(t *testing.T) {
	t.Parallel()
	for _, needle := range []string{
		"ConnectStreamLegUpload",
		"relayTunnelSetBidiUploadActive(bidi, true)",
		"relayTunnelCopyBufferBidiUploadLeg",
		"relayTunnelCopyBuffer(io.Discard, targetConn)",
	} {
		if !strings.Contains(relayGoAuditSource, needle) {
			t.Fatalf("relay.go missing H3-L1c-6 anchor %q", needle)
		}
	}
	if !strings.Contains(relayGoAuditSource, "legRole string") {
		t.Fatal("relay.go missing legRole parameter on relayTCPTunnelBidiStream")
	}
	for _, needle := range []string{
		"relayTunnelSetBidiUploadActive",
		"relayTunnelWakeBidiUploadLeg",
		"relayTunnelCopyBufferBidiUploadLeg",
		"MasqueRepromoteBidiSendBoost",
	} {
		if !strings.Contains(relayBidiBoostAuditSource, needle) {
			t.Fatalf("relay_bidi_boost.go missing H3-L1c-6 anchor %q", needle)
		}
	}
}

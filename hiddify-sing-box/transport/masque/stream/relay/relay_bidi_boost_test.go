package relay

import (
	"strings"
	"testing"
)

// TestRelayTunnelBidiDownloadBoostWireLock: H3 hijack relay must enable download send before duplex goroutines.
func TestRelayTunnelBidiDownloadBoostWireLock(t *testing.T) {
	t.Parallel()
	bundle := relayGoAuditBundle()
	idxFn := strings.Index(bundle, "func relayTCPTunnelBidiStream")
	if idxFn < 0 {
		t.Fatal("relay.go missing relayTCPTunnelBidiStream")
	}
	section := bundle[idxFn:]
	idxActive := strings.Index(section, "enableDownloadSend()")
	idxGo := strings.Index(section, "go func() {")
	if idxActive < 0 || idxGo < 0 || idxActive > idxGo {
		t.Fatalf(
			"relayTCPTunnelBidiStream: enableDownloadSend must precede first go func (active=%d go=%d)",
			idxActive, idxGo,
		)
	}
	for _, needle := range []string{
		"relayH3ProbeUploadLeg",
		"relayTunnelDownloadRelayH3Plain(bidi, targetConn)",
		"relayTunnelCopyBufferH3BidiUpload(targetConn, uploadSrc, bidi)",
		"relayTunnelPrimeDownload(src)",
		"defer func() { _ = bidi.Close() }",
	} {
		if !strings.Contains(bundle, needle) {
			t.Fatalf("relay.go missing relay anchor %q", needle)
		}
	}
}

// TestRelayHijackReleaseRequestBody (REF1-2-field-vps): CONNECT hijack must release req.Body
// after HTTPStream takeover (parity client tunnel_from_response ReleaseHTTPStream).
func TestRelayHijackReleaseRequestBody(t *testing.T) {
	t.Parallel()
	bundle := relayGoAuditBundle()
	for _, needle := range []string{
		"releaseConnectRelayRequestBody(reqBody)",
		"ReleaseHTTPStream()",
	} {
		if !strings.Contains(bundle, needle) {
			t.Fatalf("relay.go missing REF1-2 hijack release anchor %q", needle)
		}
	}
}


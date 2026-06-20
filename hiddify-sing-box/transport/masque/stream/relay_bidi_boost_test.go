package stream

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed relay_bidi_boost.go
var relayBidiBoostAuditSource string

// TestRelayTunnelBidiDownloadBoostWireLock: H3 hijack relay must enable download send before duplex goroutines.
func TestRelayTunnelBidiDownloadBoostWireLock(t *testing.T) {
	t.Parallel()
	idxFn := strings.Index(relayGoAuditSource, "func relayTCPTunnelBidiStream")
	if idxFn < 0 {
		t.Fatal("relay.go missing relayTCPTunnelBidiStream")
	}
	section := relayGoAuditSource[idxFn:]
	idxActive := strings.Index(section, "EnableMasqueRelayDownloadSend(str)")
	idxGo := strings.Index(section, "go func() {")
	if idxActive < 0 || idxGo < 0 || idxActive > idxGo {
		t.Fatalf(
			"relayTCPTunnelBidiStream: EnableMasqueRelayDownloadSend must precede first go func (active=%d go=%d)",
			idxActive, idxGo,
		)
	}
	for _, needle := range []string{
		"relayH3ProbeUploadLeg",
		"relayTunnelDownloadRelayH3Plain(bidi, targetConn)",
		"relayTunnelCopyBufferH3BidiUpload(targetConn, uploadSrc, bidi)",
		"relayTunnelPrimeDownload(src)",
	} {
		if !strings.Contains(relayGoAuditSource, needle) {
			t.Fatalf("relay.go missing relay anchor %q", needle)
		}
	}
}

// TestRelayHijackReleaseRequestBody (REF1-2-field-vps): CONNECT hijack must release req.Body
// after HTTPStream takeover (parity client tunnel_from_response ReleaseHTTPStream).
func TestRelayHijackReleaseRequestBody(t *testing.T) {
	t.Parallel()
	for _, needle := range []string{
		"releaseConnectRelayRequestBody(reqBody)",
		"ReleaseHTTPStream()",
	} {
		if !strings.Contains(relayGoAuditSource, needle) {
			t.Fatalf("relay.go missing REF1-2 hijack release anchor %q", needle)
		}
	}
}

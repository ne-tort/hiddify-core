package stream

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed relay_bidi_boost.go
var relayBidiBoostAuditSource string

func TestRelayTunnelSetBidiDownloadActiveNilSafe(t *testing.T) {
	relayTunnelSetBidiDownloadActive(nil, true)
	relayTunnelSetBidiDownloadActive(struct{}{}, true)
}

// TestRelayTunnelBidiDownloadBoostWireLock (REF-SRC-SB-5): H3 hijack relay must call
// relayTunnelSetBidiDownloadActive before duplex goroutines (parity h3.TunnelConn WriteTo).
func TestRelayTunnelBidiDownloadBoostWireLock(t *testing.T) {
	t.Parallel()
	idxFn := strings.Index(relayGoAuditSource, "func relayTCPTunnelBidiStream")
	if idxFn < 0 {
		t.Fatal("relay.go missing relayTCPTunnelBidiStream")
	}
	section := relayGoAuditSource[idxFn:]
	idxActive := strings.Index(section, "relayTunnelSetBidiDownloadActive(bidi, true)")
	idxGo := strings.Index(section, "go func() {")
	if idxActive < 0 || idxGo < 0 || idxActive > idxGo {
		t.Fatalf(
			"relayTCPTunnelBidiStream: relayTunnelSetBidiDownloadActive must precede first go func (active=%d go=%d)",
			idxActive, idxGo,
		)
	}
	for _, needle := range []string{
		"relayTunnelSetBidiDownloadActive(bidi, true)",
		"defer relayTunnelSetBidiDownloadActive(bidi, false)",
		"relayTunnelDownloadRelayH3Bidi(bidi, targetConn, bidi)",
		"relayTunnelCopyBufferBidiUpload(targetConn, uploadSrc, bidi)",
		"relayTunnelPrimeDownload(src)",
	} {
		if !strings.Contains(relayGoAuditSource, needle) {
			t.Fatalf("relay.go missing REF-SRC-SB-5 anchor %q", needle)
		}
	}
	for _, needle := range []string{
		"quic.MasqueSetBidiDownloadActive",
		"quic.MasquePokeDownloadReceiveWindow",
		"quic.MasqueWakeBidiDuplex",
		"MASQUE_RELAY_BIDI_DOWNLOAD_WRITE_WAKE",
		"relayTunnelWakeBidiAfterUploadRead",
	} {
		if !strings.Contains(relayBidiBoostAuditSource, needle) {
			t.Fatalf("relay_bidi_boost.go missing anchor %q", needle)
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

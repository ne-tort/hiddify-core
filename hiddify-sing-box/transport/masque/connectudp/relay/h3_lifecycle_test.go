package relay

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed h3_asymmetric.go
var h3RelayAsymmetricSource string

// TestProxyConnectedSocketWaitsRelayBeforeShutdown: upstream masque-go closes stream in relay goroutines, then wg.Wait.
func TestProxyConnectedSocketWaitsRelayBeforeShutdown(t *testing.T) {
	t.Parallel()
	idxFn := strings.Index(h3RelayProdSource, "func (s *Proxy) ProxyConnectedSocket")
	if idxFn < 0 {
		t.Fatal("missing ProxyConnectedSocket")
	}
	section := h3RelayProdSource[idxFn:]
	idxWait := strings.Index(section, "wg.Wait()")
	if idxWait < 0 {
		t.Fatal("missing wg.Wait in ProxyConnectedSocket")
	}
	if !strings.Contains(section, "SkipRequestStreamCapsules(") {
		t.Fatal("SkipRequestStreamCapsules must run in ProxyConnectedSocket")
	}
	afterWait := section[idxWait:]
	if strings.Contains(afterWait, "shutdownStream()") || strings.Contains(afterWait, "shutdownUDP()") {
		t.Fatal("legacy shutdown helpers must be CUT (upstream masque-go shape)")
	}
}

// TestProxyDialDoesNotDeferCloseConnectedSocket (UDP-BUG-03): Proxy transfers UDP ownership to ProxyConnectedSocket.
func TestProxyDialDoesNotDeferCloseConnectedSocket(t *testing.T) {
	t.Parallel()
	idxFn := strings.Index(h3RelayProdSource, "func (s *Proxy) Proxy(w http.ResponseWriter")
	if idxFn < 0 {
		t.Fatal("missing Proxy")
	}
	section := h3RelayProdSource[idxFn:]
	idxReturn := strings.Index(section, "return s.ProxyConnectedSocket")
	if idxReturn < 0 {
		t.Fatal("Proxy must delegate to ProxyConnectedSocket")
	}
	if strings.Contains(section[:idxReturn], "defer conn.Close()") {
		t.Fatal("Proxy must not defer conn.Close when ProxyConnectedSocket owns shutdown")
	}
}

// TestH3AsymmetricDownloadLegWaitsRelayBeforeShutdown: H2 download-leg parity — wg.Wait before teardown.
func TestH3AsymmetricDownloadLegWaitsRelayBeforeShutdown(t *testing.T) {
	t.Parallel()
	idxFn := strings.Index(h3RelayAsymmetricSource, "func serveH3DownloadLeg")
	if idxFn < 0 {
		t.Fatal("missing serveH3DownloadLeg")
	}
	section := h3RelayAsymmetricSource[idxFn:]
	idxNext := strings.Index(section[1:], "func serveH3UploadLeg")
	if idxNext > 0 {
		section = section[:idxNext+1]
	}
	idxWait := strings.Index(section, "wg.Wait()")
	if idxWait < 0 {
		t.Fatal("missing wg.Wait in serveH3DownloadLeg")
	}
	if !strings.Contains(section, "proxyConnReceive(r.Context(), conn, str)") {
		t.Fatal("serveH3DownloadLeg must run proxyConnReceive with request context")
	}
	afterWait := section[idxWait:]
	if strings.Contains(afterWait, "shutdownStream()") {
		t.Fatal("serveH3DownloadLeg must not shutdownStream before wg.Wait (keeps S2C SendDatagram alive)")
	}
}

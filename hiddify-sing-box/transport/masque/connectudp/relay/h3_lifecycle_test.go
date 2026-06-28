package relay

import (
	"strings"
	"testing"
)

// TestProxyConnectedSocketWaitsRelayBeforeShutdown (UDP-BUG-01): duplex goroutines must finish before UDP/stream close.
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
	relayBody := section[strings.Index(section, "go func() {"):idxWait]
	if strings.Contains(relayBody, "str.Close()") || strings.Contains(relayBody, "conn.Close()") {
		t.Fatal("relay goroutines must not close stream/socket directly")
	}
	idxSkip := strings.Index(section, "SkipRequestStreamCapsules(")
	if idxSkip < 0 || idxSkip > idxWait {
		t.Fatal("SkipRequestStreamCapsules must run before wg.Wait")
	}
	betweenSkipAndWait := section[idxSkip:idxWait]
	if !strings.Contains(betweenSkipAndWait, "shutdownStream()") || !strings.Contains(betweenSkipAndWait, "shutdownUDP()") {
		t.Fatal("ProxyConnectedSocket must signal shutdown after SkipRequestStreamCapsules and before wg.Wait")
	}
	afterWait := section[idxWait:]
	if !strings.Contains(afterWait, "shutdownStream()") {
		t.Fatal("ProxyConnectedSocket must idempotently shutdown after wg.Wait")
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

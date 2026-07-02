package relay

import (
	_ "embed"
	"strings"
	"testing"
)

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


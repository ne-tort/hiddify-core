package relay

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed h3.go
var h3RelayProdSource string

//go:embed h3_c2s.go
var h3RelayC2SSource string

//go:embed h3_s2c.go
var h3RelayS2CSource string

// TestProdRelaySourceHasNoServerS2CNoWakeBatch ensures UDP-M3-03 stays CUT in prod relay (W-UDP-1 REPLACE shape).
func TestProdRelaySourceHasNoServerS2CNoWakeBatch(t *testing.T) {
	t.Parallel()
	combined := h3RelayProdSource + h3RelayC2SSource + h3RelayS2CSource
	for _, needle := range []string{"SendDatagramNoWake", "s2cBatchAllowed", "FlushProxiedIPDatagramSend"} {
		if strings.Contains(combined, needle) {
			t.Fatalf("prod connectudp/relay/h3*.go must not contain %q (server NoWake batch is masque_ref only)", needle)
		}
	}
}

// TestProdRelaySourceHasC2STryReceiveDrain locks R1 masque-go C2S drain in proxyConnSend (research #1).
func TestProdRelaySourceHasC2STryReceiveDrain(t *testing.T) {
	t.Parallel()
	for _, needle := range []string{"TryReceiveDatagram", "proxyConnTryDrainMax", "drainQueued", "isTransientHTTPDatagramReceiveError"} {
		if !strings.Contains(h3RelayC2SSource, needle) {
			t.Fatalf("prod connectudp/relay/h3_c2s.go must contain %q (C2S masque-go parity)", needle)
		}
	}
}

//go:embed h3_tune.go
var h3RelayTuneSource string

// TestProdRelaySourceHasC2SICMPRelayOnWrite locks R3 masque-go C2S ICMP relay on onward Write refused.
func TestProdRelaySourceHasC2SICMPRelayOnWrite(t *testing.T) {
	t.Parallel()
	c2sICMP := h3RelayC2SSource + h3RelayTuneSource
	for _, needle := range []string{"c2sRelayUDPWrite", "icmpRelay"} {
		if !strings.Contains(c2sICMP, needle) {
			t.Fatalf("prod connectudp/relay C2S path must contain %q (C2S ICMP relay parity)", needle)
		}
	}
	if !strings.Contains(h3RelayC2SSource, "relayICMP") {
		t.Fatal("h3_c2s.go must relay ICMP via relayICMP when onward.Queue reports unreachable")
	}
}

// TestProdRelayCloseClearsClosersUnderLock locks R4: closers=nil only under mx after refCount.Wait.
func TestProdRelayCloseClearsClosersUnderLock(t *testing.T) {
	t.Parallel()
	wait := strings.Index(h3RelayProdSource, "s.refCount.Wait()")
	if wait < 0 {
		t.Fatal("missing refCount.Wait in h3.go")
	}
	tail := h3RelayProdSource[wait:]
	nilIdx := strings.Index(tail, "s.closers = nil")
	lockIdx := strings.Index(tail, "s.mx.Lock()")
	if nilIdx < 0 || lockIdx < 0 || lockIdx > nilIdx {
		t.Fatalf("closers=nil must be assigned under mx after refCount.Wait (lock@%d nil@%d)", lockIdx, nilIdx)
	}
	if !strings.Contains(h3RelayProdSource, "if s.closers != nil") {
		t.Fatal("ProxyConnectedSocket must nil-check closers before delete")
	}
}

// TestProdRelaySourceHasS2CTransientSendBackoff locks R2 masque-go S2C send resilience in proxyConnReceive.
func TestProdRelaySourceHasS2CTransientSendBackoff(t *testing.T) {
	t.Parallel()
	for _, needle := range []string{"isTransientHTTPDatagramSendError", "sendBackoff"} {
		if !strings.Contains(h3RelayS2CSource, needle) {
			t.Fatalf("prod connectudp/relay/h3_s2c.go must contain %q (S2C masque-go parity)", needle)
		}
	}
}

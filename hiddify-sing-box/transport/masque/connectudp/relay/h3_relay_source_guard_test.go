package relay

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed h3.go
var h3RelayProdSource string

// TestProdRelaySourceHasNoServerS2CNoWakeBatch ensures UDP-M3-03 stays CUT in prod relay (W-UDP-1 REPLACE shape).
func TestProdRelaySourceHasNoServerS2CNoWakeBatch(t *testing.T) {
	t.Parallel()
	for _, needle := range []string{"SendDatagramNoWake", "s2cBatchAllowed", "FlushProxiedIPDatagramSend"} {
		if strings.Contains(h3RelayProdSource, needle) {
			t.Fatalf("prod connectudp/relay/h3.go must not contain %q (server NoWake batch is masque_ref only)", needle)
		}
	}
}

// TestProdRelaySourceHasC2STryReceiveDrain locks R1 masque-go C2S drain in proxyConnSend (research #1).
func TestProdRelaySourceHasC2STryReceiveDrain(t *testing.T) {
	t.Parallel()
	for _, needle := range []string{"TryReceiveDatagram", "proxyConnTryDrainMax", "drainQueued", "isTransientHTTPDatagramReceiveError"} {
		if !strings.Contains(h3RelayProdSource, needle) {
			t.Fatalf("prod connectudp/relay/h3.go must contain %q (C2S masque-go parity)", needle)
		}
	}
}

// TestProdRelaySourceHasC2SICMPRelayOnWrite locks R3 masque-go C2S ICMP relay on onward Write refused.
func TestProdRelaySourceHasC2SICMPRelayOnWrite(t *testing.T) {
	t.Parallel()
	for _, needle := range []string{"c2sRelayUDPWrite", "icmpRelay"} {
		if !strings.Contains(h3RelayProdSource, needle) {
			t.Fatalf("prod connectudp/relay/h3.go must contain %q (C2S ICMP relay parity)", needle)
		}
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
		if !strings.Contains(h3RelayProdSource, needle) {
			t.Fatalf("prod connectudp/relay/h3.go must contain %q (S2C masque-go parity)", needle)
		}
	}
}

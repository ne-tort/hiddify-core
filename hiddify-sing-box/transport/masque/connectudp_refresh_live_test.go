package masque

import (
	"errors"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/session"
	"golang.org/x/net/http2"
)

// TestRefreshUDPAfterDialFailureKeepsH2PoolWithLiveFlows covers AUDIT B15 / TASKS F3.3:
// two live flows → failed third dial must not reset shared H2UDPTransport.
func TestRefreshUDPAfterDialFailureKeepsH2PoolWithLiveFlows(t *testing.T) {
	cs := newTestCoreSession(session.CoreSession{})
	session.StoreUDPHTTPLayer(&cs.CoreSession, option.MasqueHTTPLayerH2)
	tr := &http2.Transport{}
	cs.H2UDPTransport = tr

	flow1 := cs.trackUDPPacketConn(&stubUDPPacketConn{})
	flow2 := cs.trackUDPPacketConn(&stubUDPPacketConn{})
	if cs.liveUDPPacketConnCount() != 2 {
		t.Fatalf("live=%d want 2", cs.liveUDPPacketConnCount())
	}

	host := connectUDPPlaneHost{s: cs}
	_, _ = host.RefreshUDPAfterDialFailure(nil)
	if cs.H2UDPTransport != tr {
		t.Fatal("H2 pool reset while live flows exist — neighbors would die (B15)")
	}

	_ = flow1.Close()
	_ = flow2.Close()
	if cs.liveUDPPacketConnCount() != 0 {
		t.Fatalf("live after close=%d", cs.liveUDPPacketConnCount())
	}

	_, _ = host.RefreshUDPAfterDialFailure(nil)
	if cs.H2UDPTransport == tr {
		t.Fatal("expected H2 pool reset when no live flows")
	}
	if cs.H2UDPTransport != nil {
		t.Fatal("expected H2UDPTransport nil after reset")
	}
}

// TestHTTPFallbackRefusesWithLiveUDPFlows covers AUDIT B16: auto H3↔H2 pivot must not run
// while CONNECT-UDP PacketConns are tracked (would CloseAllH2 + UDPClient under neighbors).
func TestHTTPFallbackRefusesWithLiveUDPFlows(t *testing.T) {
	cs := newTestCoreSession(session.CoreSession{HTTPLayerAuto: true})
	session.StoreUDPHTTPLayer(&cs.CoreSession, option.MasqueHTTPLayerH3)
	_ = cs.trackUDPPacketConn(&stubUDPPacketConn{})
	if cs.tryHTTPFallbackSwitch(errors.New("Extended CONNECT refused")) {
		t.Fatal("expected no http layer fallback with live UDP flow")
	}
	if session.CurrentUDPHTTPLayer(&cs.CoreSession) != option.MasqueHTTPLayerH3 {
		t.Fatal("overlay must stay h3")
	}
}

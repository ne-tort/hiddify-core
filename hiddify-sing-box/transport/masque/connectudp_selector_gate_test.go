package masque

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	qmasque "github.com/quic-go/masque-go"
	"github.com/sagernet/sing-box/transport/masque/session"
	M "github.com/sagernet/sing/common/metadata"
)

// TestGATEConnectUDPOutboundSelectorChangeMidSession ensures deselected masque endpoint tears down
// CONNECT-UDP plane (UDPClient + H2 transport cache) while the core session stays alive (LIFE-3).
func TestGATEConnectUDPOutboundSelectorChangeMidSession(t *testing.T) {
	t.Parallel()
	cs := newTestCoreSession(session.CoreSession{
		UDPClient: &qmasque.Client{},
	})
	cs.CloseConnectUDPPlane()
	if cs.UDPClient != nil {
		t.Fatal("expected UDPClient cleared after selector deselect plane close")
	}
}

// TestGATEConnectUDPOutboundSelectorChangeActivePlane closes an active CONNECT-UDP plane mid-flow (LIFE-3).
func TestGATEConnectUDPOutboundSelectorChangeActivePlane(t *testing.T) {
	t.Parallel()
	trackConnectUDPGoroutines(t)

	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})
	sess := startConnectUDPMasqueSession(t, proxyPort)
	cs, ok := sess.(*coreSession)
	if !ok {
		t.Fatalf("need *coreSession, got %T", sess)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	pkt, err := cs.ListenPacket(ctx, M.Socksaddr{
		Addr: netip.MustParseAddr("127.0.0.1"),
		Port: 9,
	})
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	if cs.UDPClient == nil {
		t.Fatal("expected UDPClient after ListenPacket")
	}

	readDone := make(chan struct{})
	go func() {
		buf := make([]byte, 64)
		_, _, _ = pkt.ReadFrom(buf)
		close(readDone)
	}()
	time.Sleep(20 * time.Millisecond)

	cs.CloseConnectUDPPlane()
	if cs.UDPClient != nil {
		t.Fatal("expected UDPClient cleared after plane close on active flow")
	}

	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked ReadFrom did not unblock after plane close")
	}

	// Session stays alive; plane can be re-opened on next ListenPacket.
	pkt2, err := cs.ListenPacket(ctx, M.Socksaddr{
		Addr: netip.MustParseAddr("127.0.0.1"),
		Port: 9,
	})
	if err != nil {
		t.Fatalf("ListenPacket after plane close: %v", err)
	}
	defer func() { _ = pkt2.Close() }()
	if cs.UDPClient == nil {
		t.Fatal("expected UDPClient re-created after re-dial")
	}
	_ = pkt.Close()
}

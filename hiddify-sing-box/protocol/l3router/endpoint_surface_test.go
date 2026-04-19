package l3routerendpoint

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	rt "github.com/sagernet/sing-box/common/l3router"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func newEndpointForSurfaceTest(t *testing.T) *Endpoint {
	t.Helper()
	loggerFactory := log.NewNOPFactory()
	ep, err := NewEndpoint(context.Background(), nil, loggerFactory.Logger(), "l3router-test", option.L3RouterEndpointOptions{})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	return ep.(*Endpoint)
}

func TestEndpointReadinessLifecycle(t *testing.T) {
	ep := newEndpointForSurfaceTest(t)
	if ep.IsReady() {
		t.Fatal("endpoint should not be ready before Start(PostStart)")
	}
	if err := ep.Start(0); err != nil {
		t.Fatalf("Start(init): %v", err)
	}
	if ep.IsReady() {
		t.Fatal("endpoint should remain not-ready before PostStart")
	}
	if err := ep.Start(2); err != nil {
		t.Fatalf("Start(post-start): %v", err)
	}
	if !ep.IsReady() {
		t.Fatal("endpoint should become ready after PostStart")
	}
}

func TestEndpointOutboundSurfaceUnsupported(t *testing.T) {
	ep := newEndpointForSurfaceTest(t)
	if _, err := ep.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.1.1.1:443")); err == nil {
		t.Fatal("DialContext must be unsupported")
	}
	if _, err := ep.ListenPacket(context.Background(), M.ParseSocksaddr("1.1.1.1:53")); err == nil {
		t.Fatal("ListenPacket must be unsupported")
	}
}

func TestEndpointInboundTCPRejected(t *testing.T) {
	ep := newEndpointForSurfaceTest(t)
	local, remote := net.Pipe()
	defer remote.Close()
	called := false
	ep.NewConnectionEx(context.Background(), local, adapter.InboundContext{}, func(err error) {
		called = true
	})
	if !called {
		t.Fatal("onClose must be called on TCP rejection")
	}
}

func TestEndpointDefaultPacketFilterDisabledFromOptions(t *testing.T) {
	loggerFactory := log.NewNOPFactory()
	epAny, err := NewEndpoint(context.Background(), nil, loggerFactory.Logger(), "pf-off", option.L3RouterEndpointOptions{
		Peers: []option.L3RouterPeerOptions{
			{
				PeerID:          1,
				User:            "owner-a",
				FilterSourceIPs: []string{"10.0.0.0/24"},
				AllowedIPs:      []string{"10.0.0.0/24"},
			},
			{
				PeerID:          2,
				User:            "owner-b",
				FilterSourceIPs: []string{"10.0.1.0/24"},
				AllowedIPs:      []string{"10.0.1.0/24"},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	ep := epAny.(*Endpoint)
	ep.enterSession("owner-a")
	ep.enterSession("owner-b")
	t.Cleanup(func() {
		ep.leaveSession("owner-b")
		ep.leaveSession("owner-a")
		_ = ep.Close()
	})

	pkt := makeIPv4([4]byte{192, 168, 1, 1}, [4]byte{10, 0, 1, 2})
	ingressPeer, ok := ep.ingressPeerForSession(rt.SessionKey("owner-a"))
	if !ok {
		t.Fatal("missing ingress peer binding for owner-a")
	}
	d := ep.engine.HandleIngressPeer(pkt, ingressPeer)
	if d.Action != rt.ActionForward || d.EgressPeerID != rt.PeerID(2) {
		t.Fatalf("expected forward with default packet_filter=false, got %+v", d)
	}
}

func TestEndpointPacketFilterOptionEnforcesPolicy(t *testing.T) {
	loggerFactory := log.NewNOPFactory()
	epAny, err := NewEndpoint(context.Background(), nil, loggerFactory.Logger(), "pf-on", option.L3RouterEndpointOptions{
		PacketFilter: true,
		Peers: []option.L3RouterPeerOptions{
			{
				PeerID:               1,
				User:                 "owner-a",
				FilterSourceIPs:      []string{"10.0.0.0/24"},
				FilterDestinationIPs: []string{"10.0.1.0/24"},
				AllowedIPs:           []string{"10.0.0.0/24"},
			},
			{
				PeerID:     2,
				User:       "owner-b",
				AllowedIPs: []string{"10.0.1.0/24"},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	ep := epAny.(*Endpoint)
	ep.enterSession("owner-a")
	ep.enterSession("owner-b")
	t.Cleanup(func() {
		ep.leaveSession("owner-b")
		ep.leaveSession("owner-a")
		_ = ep.Close()
	})

	badSrc := makeIPv4([4]byte{192, 168, 1, 1}, [4]byte{10, 0, 1, 2})
	ingressPeer, ok := ep.ingressPeerForSession(rt.SessionKey("owner-a"))
	if !ok {
		t.Fatal("missing ingress peer binding for owner-a")
	}
	if d := ep.engine.HandleIngressPeer(badSrc, ingressPeer); d.Action != rt.ActionDrop || d.DropReason != rt.DropFilterSource {
		t.Fatalf("expected source filter drop, got %+v", d)
	}

	badDst := makeIPv4([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 9, 9})
	if d := ep.engine.HandleIngressPeer(badDst, ingressPeer); d.Action != rt.ActionDrop || d.DropReason != rt.DropFilterDestination {
		t.Fatalf("expected destination filter drop, got %+v", d)
	}

	// Empty filter lists on route 2 means allow-all even when packet filter is enabled.
	r2 := rt.Route{
		PeerID:               2,
		User:                 "owner-b",
		FilterSourceIPs:      nil,
		FilterDestinationIPs: nil,
		AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
	}
	if err := ep.UpsertRoute(r2); err != nil {
		t.Fatalf("upsert route2: %v", err)
	}
	good := makeIPv4([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 1, 2})
	if d := ep.engine.HandleIngressPeer(good, ingressPeer); d.Action != rt.ActionForward {
		t.Fatalf("expected forward with empty filter lists treated as allow-all, got %+v", d)
	}
}

func TestEndpointLookupBackendOptionValidation(t *testing.T) {
	loggerFactory := log.NewNOPFactory()
	if _, err := NewEndpoint(context.Background(), nil, loggerFactory.Logger(), "backend-bad", option.L3RouterEndpointOptions{
		LookupBackend: "invalid_backend",
	}); err == nil {
		t.Fatalf("expected invalid lookup backend error")
	}
}

func TestEndpointInterfaceUpdatedResetsVolatileStateIdempotent(t *testing.T) {
	ep := newEndpointForSurfaceTest(t)
	if err := ep.Start(adapter.StartStatePostStart); err != nil {
		t.Fatalf("Start(post-start): %v", err)
	}

	ep.InterfaceUpdated()
	ep.InterfaceUpdated()

	if !ep.IsReady() {
		t.Fatal("endpoint should remain ready after interface updates")
	}
	if depth := ep.SnapshotMetrics().QueueDepth; depth != 0 {
		t.Fatalf("expected queue depth to be reset, got %d", depth)
	}
	metrics := ep.SnapshotMetrics()
	if metrics.NetworkResets != 2 {
		t.Fatalf("expected NetworkResets=2, got %d", metrics.NetworkResets)
	}
}

func TestEndpointTrackerMatchesOnlyOwnOutbound(t *testing.T) {
	ep := newEndpointForSurfaceTest(t)
	otherAny, err := NewEndpoint(context.Background(), nil, log.NewNOPFactory().Logger(), "another-l3router", option.L3RouterEndpointOptions{})
	if err != nil {
		t.Fatalf("NewEndpoint(other): %v", err)
	}
	other := otherAny.(*Endpoint)

	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	gotOwn := ep.RoutedConnection(context.Background(), local, adapter.InboundContext{}, nil, ep)
	if gotOwn != local {
		t.Fatal("tracker should keep original conn for own outbound")
	}
	gotOther := ep.RoutedConnection(context.Background(), local, adapter.InboundContext{}, nil, other)
	if gotOther != local {
		t.Fatal("tracker should keep original conn for non-matching outbound")
	}
}

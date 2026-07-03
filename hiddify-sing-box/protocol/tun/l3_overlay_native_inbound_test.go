package tun

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	singtun "github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"
)

type stubNativeL3Outbound struct {
	*outbound.Adapter
	ready bool
	calls int
}

func newStubNativeL3Outbound() *stubNativeL3Outbound {
	a := outbound.NewAdapter("masque", "masque-client", nil, nil)
	return &stubNativeL3Outbound{Adapter: &a, ready: true}
}

func (s *stubNativeL3Outbound) IsReady() bool { return s.ready }

func (s *stubNativeL3Outbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, nil
}

func (s *stubNativeL3Outbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, nil
}

func (s *stubNativeL3Outbound) WireConnectIPNativeL3(
	_ context.Context,
	_ singtun.Tun,
	routePrefixes []netip.Prefix,
	_ netip.Addr,
	_ netip.Addr,
) (*L3OverlayNativeWire, bool, error) {
	s.calls++
	return &L3OverlayNativeWire{
		Prefixes:     routePrefixes,
		Send:         func([]byte) error { return nil },
		SendErr:      func(error) {},
		StartIngress: func(context.Context) error { return nil },
		Stop:         func() {},
	}, true, nil
}

type stubOutboundManager struct {
	ob adapter.Outbound
}

func (m stubOutboundManager) Start(adapter.StartStage) error { return nil }
func (m stubOutboundManager) Close() error                   { return nil }
func (m stubOutboundManager) Outbounds() []adapter.Outbound  { return nil }
func (m stubOutboundManager) Outbound(string) (adapter.Outbound, bool) {
	if m.ob == nil {
		return nil, false
	}
	return m.ob, true
}
func (m stubOutboundManager) Default() adapter.Outbound { return nil }
func (m stubOutboundManager) Remove(string) error       { return nil }
func (m stubOutboundManager) Create(context.Context, adapter.Router, log.ContextLogger, string, string, any) error {
	return nil
}

func TestResolveL3OverlayNativeOutbound(t *testing.T) {
	stub := newStubNativeL3Outbound()
	wire, err := resolveL3OverlayNativeOutbound(stubOutboundManager{ob: stub}, "masque-client")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if wire == nil {
		t.Fatal("expected wire outbound")
	}
	_, err = resolveL3OverlayNativeOutbound(stubOutboundManager{}, "missing")
	if err == nil {
		t.Fatal("expected error for missing outbound")
	}
}

func TestTryWireNativeConnectIPL3(t *testing.T) {
	stub := newStubNativeL3Outbound()
	in := &Inbound{
		l3OverlayPrefixes: []netip.Prefix{netip.MustParsePrefix("172.30.99.0/24")},
		l3OverlayTunHost:  netip.MustParseAddr("172.30.99.2"),
	}
	prefixes, send, _, wired, err := in.tryWireNativeConnectIPL3(context.Background(), nil, stub)
	if err != nil {
		t.Fatalf("tryWire: %v", err)
	}
	if !wired {
		t.Fatal("expected wired=true")
	}
	if send == nil || len(prefixes) == 0 {
		t.Fatal("expected L3 hooks")
	}
	if stub.calls != 1 {
		t.Fatalf("wire calls=%d want 1", stub.calls)
	}
}

func TestFirstTunInet4(t *testing.T) {
	route := []netip.Prefix{netip.MustParsePrefix("172.30.99.0/24")}
	inet4 := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.1/32"),
		netip.MustParsePrefix("172.30.99.2/32"),
	}
	got := firstTunInet4(inet4, route)
	want := netip.MustParseAddr("172.30.99.2")
	if got != want {
		t.Fatalf("firstTunInet4=%v want %v", got, want)
	}
	if firstTunInet4(nil, route).IsValid() {
		t.Fatal("expected invalid when no inet4")
	}
}

var _ L3OverlayNativeOutbound = (*stubNativeL3Outbound)(nil)

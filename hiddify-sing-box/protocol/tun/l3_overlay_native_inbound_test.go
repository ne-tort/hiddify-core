package tun

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/metadata"
)

type stubNativeOutbound struct {
	wire *L3OverlayNativeWire
	ok   bool
	err  error
}

func (s *stubNativeOutbound) WireConnectIPNativeL3(
	_ context.Context,
	_ tun.Tun,
	_ []netip.Prefix,
	_, _ netip.Addr,
) (*L3OverlayNativeWire, bool, error) {
	return s.wire, s.ok, s.err
}

type stubNonNativeOutbound struct{}

type stubTun struct{}

func (stubTun) Read([]byte) (int, error)  { return 0, nil }
func (stubTun) Write([]byte) (int, error) { return 0, nil }
func (stubTun) Name() (string, error)     { return "stub0", nil }
func (stubTun) Start() error              { return nil }
func (stubTun) Close() error              { return nil }
func (stubTun) UpdateRouteOptions(tun.Options) error { return nil }

func testInboundWithNative(tag string, ctx context.Context) *Inbound {
	return &Inbound{
		ctx:                  ctx,
		l3OverlayOutboundTag:   tag,
		l3OverlayPrefixes:    []netip.Prefix{netip.MustParsePrefix("172.30.99.0/24")},
		l3OverlaySocksDest:   metadata.ParseSocksaddr("198.18.0.1:33333"),
		tunOptions:           tun.Options{Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.100.2/31")}},
	}
}

func TestResolveL3OverlayNativeOutboundDirect(t *testing.T) {
	t.Parallel()
	native := &stubNativeOutbound{ok: true}
	in := testInboundWithNative("masque-client", context.Background())
	if got := in.resolveL3OverlayNativeOutbound(native); got != native {
		t.Fatal("expected direct L3OverlayNativeOutbound")
	}
}

func TestResolveL3OverlayNativeOutboundEmptyTag(t *testing.T) {
	t.Parallel()
	in := testInboundWithNative("", context.Background())
	if got := in.resolveL3OverlayNativeOutbound(&stubNonNativeOutbound{}); got != nil {
		t.Fatal("expected nil when outbound tag empty")
	}
}

func TestTryWireNativeConnectIPL3Wired(t *testing.T) {
	t.Parallel()
	sendCalled := false
	wire := &L3OverlayNativeWire{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("172.30.99.0/24")},
		Send:     func([]byte) error { sendCalled = true; return nil },
		StartIngress: func(context.Context) error { return nil },
		Stop:     func() {},
	}
	native := &stubNativeOutbound{wire: wire, ok: true}
	in := testInboundWithNative("", context.Background())
	prefixes, send, _, ok, err := in.tryWireNativeConnectIPL3(context.Background(), stubTun{}, native)
	if err != nil || !ok || send == nil {
		t.Fatalf("tryWire: ok=%v err=%v send_nil=%v", ok, err, send == nil)
	}
	if len(prefixes) == 0 {
		t.Fatal("expected prefixes from wire")
	}
	if err := send([]byte{0x45}); err != nil || !sendCalled {
		t.Fatalf("send hook: called=%v err=%v", sendCalled, err)
	}
	if in.l3OverlayNativeStop == nil || in.l3OverlayNativeStart == nil {
		t.Fatal("expected native lifecycle hooks stored on inbound")
	}
}

func TestTryWireNativeConnectIPL3NotWired(t *testing.T) {
	t.Parallel()
	native := &stubNativeOutbound{ok: false}
	in := testInboundWithNative("", context.Background())
	_, _, _, ok, err := in.tryWireNativeConnectIPL3(context.Background(), stubTun{}, native)
	if err != nil || ok {
		t.Fatalf("not wired: ok=%v err=%v", ok, err)
	}
}

func TestTryWireNativeConnectIPL3WireError(t *testing.T) {
	t.Parallel()
	want := errors.New("wire fail")
	native := &stubNativeOutbound{ok: false, err: want}
	in := testInboundWithNative("", context.Background())
	_, _, _, ok, err := in.tryWireNativeConnectIPL3(context.Background(), stubTun{}, native)
	if ok || !errors.Is(err, want) {
		t.Fatalf("wire error: ok=%v err=%v want %v", ok, err, want)
	}
}

func TestTryWireNativeConnectIPL3NoNativeOutbound(t *testing.T) {
	t.Parallel()
	in := testInboundWithNative("masque-client", context.Background())
	_, _, _, ok, err := in.tryWireNativeConnectIPL3(context.Background(), stubTun{}, nil)
	if err != nil || ok {
		t.Fatalf("nil native: ok=%v err=%v", ok, err)
	}
}

func TestFirstTunInet4Host(t *testing.T) {
	t.Parallel()
	host := firstTunInet4Host(tun.Options{
		Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.100.2/31")},
	})
	want := netip.MustParseAddr("172.19.100.2")
	if host != want {
		t.Fatalf("host=%v want %v", host, want)
	}
}

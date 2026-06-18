package masque

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/service"
	M "github.com/sagernet/sing/common/metadata"
)

// testMasqueNetworkManager is a minimal adapter.NetworkManager for dialer bootstrap tests.
type testMasqueNetworkManager struct {
	autoDetect bool
}

func (testMasqueNetworkManager) Start(adapter.StartStage) error { return nil }
func (testMasqueNetworkManager) Close() error                   { return nil }
func (testMasqueNetworkManager) Initialize([]adapter.RuleSet)  {}
func (testMasqueNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}
func (testMasqueNetworkManager) UpdateInterfaces() error { return nil }
func (testMasqueNetworkManager) DefaultNetworkInterface() *adapter.NetworkInterface {
	return nil
}
func (testMasqueNetworkManager) NetworkInterfaces() []adapter.NetworkInterface { return nil }
func (t testMasqueNetworkManager) AutoDetectInterface() bool                   { return t.autoDetect }
func (testMasqueNetworkManager) AutoDetectInterfaceFunc() control.Func {
	return func(network, address string, c syscall.RawConn) error { return nil }
}
func (testMasqueNetworkManager) ProtectFunc() control.Func {
	return func(network, address string, c syscall.RawConn) error { return nil }
}
func (testMasqueNetworkManager) DefaultOptions() adapter.NetworkOptions { return adapter.NetworkOptions{} }
func (testMasqueNetworkManager) RegisterAutoRedirectOutputMark(uint32) error { return nil }
func (testMasqueNetworkManager) AutoRedirectOutputMark() uint32 { return 0 }
func (testMasqueNetworkManager) AutoRedirectOutputMarkFunc() control.Func {
	return func(network, address string, c syscall.RawConn) error { return nil }
}
func (testMasqueNetworkManager) NetworkMonitor() tun.NetworkUpdateMonitor { return nil }
func (testMasqueNetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor {
	return nil
}
func (testMasqueNetworkManager) PackageManager() tun.PackageManager { return nil }
func (testMasqueNetworkManager) NeedWIFIState() bool                { return false }
func (testMasqueNetworkManager) WIFIState() adapter.WIFIState       { return adapter.WIFIState{} }
func (testMasqueNetworkManager) UpdateWIFIState()                  {}
func (testMasqueNetworkManager) ResetNetwork()                     {}

func TestBuildQUICDialFuncUsesSingBoxDialerWhenAutoDetectInterface(t *testing.T) {
	t.Parallel()
	ctx := service.ContextWith[adapter.NetworkManager](
		context.Background(),
		testMasqueNetworkManager{autoDetect: true},
	)
	quicDial, err := buildQUICDialFunc(ctx, option.DialerOptions{}, false)
	if err != nil {
		t.Fatalf("build QUIC dial: %v", err)
	}
	if quicDial == nil {
		t.Fatal("expected non-nil QUIC dial when auto_detect_interface is enabled")
	}
}

func TestBuildQUICDialFuncTierAWhenNetworkManagerWithoutAutoDetect(t *testing.T) {
	t.Parallel()
	ctx := service.ContextWith[adapter.NetworkManager](
		context.Background(),
		testMasqueNetworkManager{autoDetect: false},
	)
	quicDial, err := buildQUICDialFunc(ctx, option.DialerOptions{}, false)
	if err != nil {
		t.Fatalf("build QUIC dial: %v", err)
	}
	if quicDial != nil {
		t.Fatal("expected Tier A quic.DialAddr when NetworkManager present but auto_detect_interface is off (docker bench shape)")
	}
}

type testMasqueDirectOutbound struct {
	outbound.Adapter
}

func (o *testMasqueDirectOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("testMasqueDirectOutbound: unused")
}

func (o *testMasqueDirectOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("testMasqueDirectOutbound: unused")
}

type testMasqueOutboundManager struct {
	outbounds []adapter.Outbound
}

func (testMasqueOutboundManager) Start(adapter.StartStage) error { return nil }
func (testMasqueOutboundManager) Close() error                   { return nil }
func (m testMasqueOutboundManager) Outbounds() []adapter.Outbound { return m.outbounds }
func (m testMasqueOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	for _, ob := range m.outbounds {
		if ob.Tag() == tag {
			return ob, true
		}
	}
	return nil, false
}
func (testMasqueOutboundManager) Default() adapter.Outbound { return nil }
func (testMasqueOutboundManager) Remove(string) error       { return nil }
func (testMasqueOutboundManager) Create(context.Context, adapter.Router, log.ContextLogger, string, string, any) error {
	return nil
}

func TestBuildQUICDialFuncTierAWhenBootstrapInjectsDirectDetour(t *testing.T) {
	t.Parallel()
	direct := &testMasqueDirectOutbound{
		Adapter: outbound.NewAdapter(C.TypeDirect, "direct", []string{"tcp", "udp"}, nil),
	}
	ctx := service.ContextWith[adapter.OutboundManager](
		context.Background(),
		testMasqueOutboundManager{outbounds: []adapter.Outbound{direct}},
	)
	ctx = service.ContextWith[adapter.NetworkManager](
		ctx,
		testMasqueNetworkManager{autoDetect: false},
	)
	effective := masqueEffectiveBootstrapDialerOptions(ctx, option.DialerOptions{})
	if effective.Detour != "direct" {
		t.Fatalf("expected bootstrap detour direct, got %q", effective.Detour)
	}
	quicDial, err := buildQUICDialFunc(ctx, option.DialerOptions{}, false)
	if err != nil {
		t.Fatalf("build QUIC dial: %v", err)
	}
	if quicDial != nil {
		t.Fatal("bootstrap detour must not force TierB custom_quic_dial when user DialerOptions are empty")
	}
}

func TestMasqueEffectiveBootstrapDialerOptionsPreservesExplicitDetour(t *testing.T) {
	t.Parallel()
	in := option.DialerOptions{Detour: "custom"}
	got := masqueEffectiveBootstrapDialerOptions(context.Background(), in)
	if got.Detour != "custom" {
		t.Fatalf("expected explicit detour preserved, got %q", got.Detour)
	}
}

func TestBuildQUICDialFuncTierAWhenNoNetworkManager(t *testing.T) {
	t.Parallel()
	quicDial, err := buildQUICDialFunc(context.Background(), option.DialerOptions{}, false)
	if err != nil {
		t.Fatalf("build QUIC dial: %v", err)
	}
	if quicDial != nil {
		t.Fatal("expected nil QUIC dial override without NetworkManager (Tier A quic.DialAddr)")
	}
}

// upstreamWrapConn mirrors sing-box conntrack.Conn (net.Conn field + Upstream(), no Unwrap).
type upstreamWrapConn struct {
	net.Conn
}

func (c *upstreamWrapConn) Upstream() any { return c.Conn }

func TestUnwrapMasqueQUICUnderlyingConnFollowsUpstream(t *testing.T) {
	t.Parallel()
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	inner, err := net.Dial("udp", ln.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer inner.Close()
	wrapped := &upstreamWrapConn{Conn: inner}
	under := unwrapMasqueQUICUnderlyingConn(wrapped)
	if _, ok := under.(interface {
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	}); !ok {
		t.Fatalf("expected kernel UDP conn under upstream wrapper, got %T", under)
	}
}

func TestBuildQUICDialFuncDomainResolverOnlyStaysTierAEvenWithAutoDetect(t *testing.T) {
	t.Parallel()
	ctx := service.ContextWith[adapter.NetworkManager](
		context.Background(),
		testMasqueNetworkManager{autoDetect: true},
	)
	quicDial, err := buildQUICDialFunc(ctx, option.DialerOptions{
		DomainResolver: &option.DomainResolveOptions{Server: "local-dns"},
	}, true)
	if err != nil {
		t.Fatalf("build QUIC dial: %v", err)
	}
	if quicDial != nil {
		t.Fatal("expected nil QUIC dial for domain_resolver-only options (Tier A), even with auto-detect")
	}
}

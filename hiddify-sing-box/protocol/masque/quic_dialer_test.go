package masque

import (
	"context"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/service"
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

func TestBuildQUICDialFuncUsesSingBoxDialerWhenNetworkManagerPresent(t *testing.T) {
	t.Parallel()
	for _, autoDetect := range []bool{true, false} {
		autoDetect := autoDetect
		t.Run(map[bool]string{true: "auto_detect", false: "no_auto_detect"}[autoDetect], func(t *testing.T) {
			t.Parallel()
			ctx := service.ContextWith[adapter.NetworkManager](
				context.Background(),
				testMasqueNetworkManager{autoDetect: autoDetect},
			)
			quicDial, err := buildQUICDialFunc(ctx, option.DialerOptions{}, false)
			if err != nil {
				t.Fatalf("build QUIC dial: %v", err)
			}
			if quicDial == nil {
				t.Fatal("expected non-nil QUIC dial when NetworkManager is present (sing-box routed bootstrap)")
			}
		})
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

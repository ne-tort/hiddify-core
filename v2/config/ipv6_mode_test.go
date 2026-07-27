package config

import (
	"context"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

func testCtx() context.Context {
	return libbox.BaseContext(nil)
}

func TestTunAddressesForIPv6Mode(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		mode    option.DomainStrategy
		ipv6OK  bool
		wantLen int
		wantV4  bool
		wantV6  bool
	}{
		{
			name:    "ipv4_only",
			mode:    option.DomainStrategy(C.DomainStrategyIPv4Only),
			ipv6OK:  true,
			wantLen: 1,
			wantV4:  true,
			wantV6:  false,
		},
		{
			name:    "ipv6_only supported",
			mode:    option.DomainStrategy(C.DomainStrategyIPv6Only),
			ipv6OK:  true,
			wantLen: 1,
			wantV4:  false,
			wantV6:  true,
		},
		{
			name:    "ipv6_only unsupported falls back v4",
			mode:    option.DomainStrategy(C.DomainStrategyIPv6Only),
			ipv6OK:  false,
			wantLen: 1,
			wantV4:  true,
			wantV6:  false,
		},
		{
			name:    "prefer_ipv4 dual stack",
			mode:    option.DomainStrategy(C.DomainStrategyPreferIPv4),
			ipv6OK:  true,
			wantLen: 2,
			wantV4:  true,
			wantV6:  true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addrs := tunAddressesForIPv6Mode(tc.mode, tc.ipv6OK)
			if len(addrs) != tc.wantLen {
				t.Fatalf("got %d prefixes, want %d", len(addrs), tc.wantLen)
			}
			hasV4 := false
			hasV6 := false
			for _, p := range addrs {
				if p.Addr().Is4() {
					hasV4 = true
				}
				if p.Addr().Is6() {
					hasV6 = true
				}
			}
			if hasV4 != tc.wantV4 || hasV6 != tc.wantV6 {
				t.Fatalf("v4=%v v6=%v, want v4=%v v6=%v", hasV4, hasV6, tc.wantV4, tc.wantV6)
			}
		})
	}
}

func TestDefaultNetworkStrategyForIPv6Mode(t *testing.T) {
	t.Parallel()

	fallbackModes := []option.DomainStrategy{
		option.DomainStrategy(C.DomainStrategyPreferIPv4),
		option.DomainStrategy(C.DomainStrategyIPv4Only),
		option.DomainStrategy(C.DomainStrategyPreferIPv6),
		option.DomainStrategy(C.DomainStrategyIPv6Only),
	}
	for _, mode := range fallbackModes {
		if got := defaultNetworkStrategyForIPv6Mode(mode); got == nil {
			t.Fatalf("expected fallback strategy for mode %v", mode)
		}
	}
	if got := defaultNetworkStrategyForIPv6Mode(option.DomainStrategy(C.DomainStrategyAsIS)); got != nil {
		t.Fatalf("expected nil strategy for as_is, got %v", got)
	}
}

func TestBuildConfigAppliesIPv6ModeOnRoute(t *testing.T) {
	t.Parallel()

	profile := `{"outbounds":[{"type":"direct","tag":"direct"}]}`
	hopts := DefaultHiddifyOptions()
	hopts.EnableTun = true
	hopts.IPv6Mode = option.DomainStrategy(C.DomainStrategyIPv4Only)

	built, err := BuildConfig(testCtx(), hopts, &ReadOptions{Content: profile})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if built.Route == nil || built.Route.DefaultNetworkStrategy == nil {
		t.Fatal("expected default_network_strategy on route")
	}
	if len(built.Inbounds) == 0 {
		t.Fatal("expected tun inbound")
	}
	tun, ok := built.Inbounds[0].Options.(*option.TunInboundOptions)
	if !ok {
		t.Fatalf("expected tun inbound options, got %T", built.Inbounds[0].Options)
	}
	if len(tun.Address) != 1 || !tun.Address[0].Addr().Is4() {
		t.Fatalf("expected ipv4-only tun prefix, got %#v", tun.Address)
	}
}

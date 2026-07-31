package includecheck_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	M "github.com/sagernet/sing/common/metadata"
)

func TestInboundTypesRegistered(t *testing.T) {
	reg := include.InboundRegistry()
	types := []string{
		"tun", "redirect", "tproxy", "direct",
		"socks", "http", "mixed",
		"shadowsocks", "snell", "vmess", "trojan", "naive", "shadowtls", "vless", "anytls",
		"hysteria", "hysteria2", "tuic",
		"mieru", "ssh", "carrier", "demux", "derp",
		"shadowquic", "sudoku", "trusttunnel", "cloudflared",
	}
	for _, typ := range types {
		typ := typ
		t.Run(typ, func(t *testing.T) {
			opts, ok := reg.CreateOptions(typ)
			if !ok {
				t.Fatalf("inbound %q missing from registry (build tag?)", typ)
			}
			err := tryCreate(func() error {
				_, e := reg.Create(nil, nil, nil, "t-"+typ, typ, opts)
				return e
			})
			if err != nil && isMissingBuildTag(err.Error()) {
				t.Fatalf("inbound %q stubbed out: %v", typ, err)
			}
		})
	}
}

func TestOutboundTypesRegistered(t *testing.T) {
	reg := include.OutboundRegistry()
	types := []string{
		"direct", "block", "bridge",
		"socks", "http", "shadowsocks", "snell", "vmess", "trojan", "naive",
		"tor", "ssh", "shadowtls", "vless", "anytls",
		"hysteria", "hysteria2", "tuic", "masque",
		"mieru", "carrier", "derp", "shadowquic", "sudoku", "trusttunnel",
		"selector", "urltest", "balancer",
	}
	for _, typ := range types {
		typ := typ
		t.Run(typ, func(t *testing.T) {
			opts, ok := reg.CreateOptions(typ)
			if !ok {
				t.Fatalf("outbound %q missing from registry (build tag?)", typ)
			}
			err := tryCreate(func() error {
				_, e := reg.CreateOutbound(nil, nil, nil, "o-"+typ, typ, opts)
				return e
			})
			if err != nil && isMissingBuildTag(err.Error()) {
				t.Fatalf("outbound %q stubbed out: %v", typ, err)
			}
		})
	}
}

func TestEndpointTypesRegistered(t *testing.T) {
	reg := include.EndpointRegistry()
	types := []string{
		"wireguard",
		"openconnect",
		"openvpn-client",
		"openvpn-server",
		"tailscale",
	}
	for _, typ := range types {
		typ := typ
		t.Run(typ, func(t *testing.T) {
			opts, ok := reg.CreateOptions(typ)
			if !ok {
				t.Fatalf("endpoint %q missing from registry (build tag?)", typ)
			}
			err := tryCreate(func() error {
				_, e := reg.Create(nil, nil, nil, "e-"+typ, typ, opts)
				return e
			})
			if err != nil && isMissingBuildTag(err.Error()) {
				t.Fatalf("endpoint %q stubbed out: %v", typ, err)
			}
		})
	}
}

func TestV2RayTransportsRegistered(t *testing.T) {
	// Blank-imported via include when with_xhttp / with_hysteria_transport are set.
	cases := []option.V2RayTransportOptions{
		{Type: "http"},
		{Type: "ws"},
		{Type: "quic"},
		{Type: "grpc"},
		{Type: "httpupgrade"},
		{Type: "xhttp"},
		{Type: "hysteria", HysteriaOptions: option.V2RayHysteriaOptions{Password: "x", Version: 2}},
	}
	for _, opts := range cases {
		opts := opts
		t.Run(opts.Type, func(t *testing.T) {
			err := tryCreate(func() error {
				_, e := v2ray.NewClientTransport(context.Background(), nil, M.Socksaddr{}, opts, nil)
				return e
			})
			if err != nil && (isMissingBuildTag(err.Error()) || strings.Contains(strings.ToLower(err.Error()), "unknown transport type")) {
				t.Fatalf("transport %q not registered: %v", opts.Type, err)
			}
		})
	}
}

func tryCreate(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return fn()
}

func isMissingBuildTag(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "not included in this build") ||
		strings.Contains(lower, "rebuild with -tags") ||
		strings.Contains(lower, "awg support is not included") ||
		strings.Contains(lower, "support not built")
}

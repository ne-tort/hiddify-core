package config

import (
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/wireguard"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestBuildWarpWireGuardEndpoint(t *testing.T) {
	ep, err := buildWarpWireGuardEndpoint(WarpWireguardConfig{
		PrivateKey:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PeerPublicKey:    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
		LocalAddressIPv4: "172.16.0.2",
		LocalAddressIPv6: "2606:4700:110::1",
		ClientID:         "AQID",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ep.Tag != WarpWGTag || ep.Type != C.TypeWireGuard {
		t.Fatalf("unexpected endpoint %#v", ep)
	}
	opts := ep.Options.(*option.WireGuardEndpointOptions)
	// Legacy path for Cloudflare WARP (single peer, full tunnel) — must not enter sugar mode.
	if opts.Subnet.IsValid() {
		t.Fatal("warp must not set sugar subnet")
	}
	if len(opts.Peers) != 1 {
		t.Fatalf("peers=%d", len(opts.Peers))
	}
	peer := opts.Peers[0]
	if peer.IP.IsValid() {
		t.Fatal("warp must not set peer.ip sugar")
	}
	if peer.ExitNode || opts.UseExitNode || opts.AdvertiseExitNode {
		t.Fatal("warp must not set exit-node sugar flags")
	}
	if len(peer.AllowedIPs) < 2 {
		t.Fatalf("legacy allowed_ips required, got %v", peer.AllowedIPs)
	}
	if len(opts.Address) != 2 {
		t.Fatalf("want v4+v6 address, got %v", opts.Address)
	}
	// Prefixable accepts host+/CIDR; builder normalizes bare IPs to /32 and /128.
	if netip.Prefix(opts.Address[0]).String() != "172.16.0.2/32" {
		t.Fatalf("v4 address=%v", opts.Address[0])
	}
	if peer.Address != "engage.cloudflareclient.com" || peer.Port != 2408 {
		t.Fatalf("peer endpoint=%s:%d", peer.Address, peer.Port)
	}
	before := append(badoption.Listable[netip.Prefix](nil), peer.AllowedIPs...)
	if err := wireguard.NormalizeWireGuardSugar(opts); err != nil {
		t.Fatalf("legacy WARP must pass sugar normalize: %v", err)
	}
	if len(opts.Peers[0].AllowedIPs) != len(before) {
		t.Fatalf("normalize mutated WARP allowed_ips: before=%v after=%v", before, opts.Peers[0].AllowedIPs)
	}
}


func TestBuildWarpMasqueOutbound(t *testing.T) {
	out, err := buildWarpMasqueOutbound(WarpMasqueConfig{
		PrivateKey: "priv",
		PublicKey:  "cHVi",
		IPv4:       "172.16.0.2",
		IPv6:       "2606:4700:110::1",
		Server:     "162.159.198.1",
		ServerPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Tag != WarpMasqueTag || out.Type != C.TypeMASQUE {
		t.Fatalf("unexpected outbound %#v", out)
	}
	opts := out.Options.(*option.MASQUEOutboundOptions)
	if opts.Profile != "cloudflare" || opts.Network != "h3" {
		t.Fatalf("opts=%+v", opts)
	}
}

func TestBuildWarpMasqueOutboundNormalizesPEMPublicKey(t *testing.T) {
	pemKey := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG
7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==
-----END PUBLIC KEY-----`
	out, err := buildWarpMasqueOutbound(WarpMasqueConfig{
		PrivateKey: "priv",
		PublicKey:  pemKey,
		IPv4:       "172.16.0.2",
		Server:     "162.159.198.1",
		ServerPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	opts := out.Options.(*option.MASQUEOutboundOptions)
	if strings.Contains(opts.PublicKey, "BEGIN PUBLIC KEY") {
		t.Fatalf("public key must be normalized, got %q", opts.PublicKey)
	}
	if _, err := base64.StdEncoding.DecodeString(opts.PublicKey); err != nil {
		t.Fatalf("normalized key must be base64: %v", err)
	}
}

func TestApplyDetourToOutbound(t *testing.T) {
	out := option.Outbound{
		Type: C.TypeVLESS,
		Tag:  "node1",
		Options: &option.VLESSOutboundOptions{
			DialerOptions: option.DialerOptions{},
		},
	}
	out = applyDetourToOutbound(out, "relay")
	opts := out.Options.(*option.VLESSOutboundOptions)
	if opts.Detour != "relay" {
		t.Fatalf("detour=%q", opts.Detour)
	}
	selector := option.Outbound{
		Type: C.TypeSelector,
		Tag:  "select",
		Options: &option.SelectorOutboundOptions{
			Outbounds: []string{"relay"},
		},
	}
	selector = applyDetourToOutbound(selector, "relay")
	// Groups are never modified.
	if selector.Type != C.TypeSelector {
		t.Fatalf("unexpected type %s", selector.Type)
	}
}

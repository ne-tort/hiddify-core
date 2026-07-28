package config

import (
	"encoding/base64"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
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

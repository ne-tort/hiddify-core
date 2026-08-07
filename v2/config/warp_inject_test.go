package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestSetOutboundsDoesNotInjectWarp(t *testing.T) {
	opt := DefaultClientOptions()
	opt.Warp = WarpOptions{
		EnableMasque:    true,
		EnableWireguard: true,
		WireguardConfig: WarpWireguardConfig{
			PrivateKey:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			PeerPublicKey:    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
			LocalAddressIPv4: "172.16.0.2",
			ClientID:         "AQID",
		},
		MasqueConfig: WarpMasqueConfig{
			PrivateKey: "priv",
			PublicKey:  "cHVi",
			IPv4:       "172.16.0.2",
			Server:     "162.159.198.1",
			ServerPort: 443,
		},
	}
	input := &option.Options{
		Outbounds: []option.Outbound{{
			Type: C.TypeVLESS,
			Tag:  "node1",
			Options: &option.VLESSOutboundOptions{
				DialerOptions: option.DialerOptions{},
			},
		}},
	}
	var out option.Options
	if err := setOutbounds(&out, input, opt, &map[string][]string{}); err != nil {
		t.Fatal(err)
	}

	for _, o := range out.Outbounds {
		if o.Tag == WarpMasqueTag {
			t.Fatal("WARP-MASQUE must not be mixed into foreign profiles")
		}
	}
	for _, e := range out.Endpoints {
		if e.Tag == WarpWGTag {
			t.Fatal("WARP-WG must not be mixed into foreign profiles")
		}
	}
}

func TestSetOutboundsKeepsDedicatedWarpProfileLeaves(t *testing.T) {
	opt := DefaultClientOptions()
	wg, err := buildWarpWireGuardEndpoint(WarpWireguardConfig{
		PrivateKey:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PeerPublicKey:    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
		LocalAddressIPv4: "172.16.0.2",
		ClientID:         "AQID",
	})
	if err != nil {
		t.Fatal(err)
	}
	mq, err := buildWarpMasqueOutbound(WarpMasqueConfig{
		PrivateKey: "priv",
		PublicKey:  "cHVi",
		IPv4:       "172.16.0.2",
		Server:     "162.159.198.1",
		ServerPort: 443,
	})
	if err != nil {
		t.Fatal(err)
	}
	input := &option.Options{
		Outbounds: []option.Outbound{*mq},
		Endpoints: []option.Endpoint{*wg},
	}
	var out option.Options
	if err := setOutbounds(&out, input, opt, &map[string][]string{}); err != nil {
		t.Fatal(err)
	}
	var foundMasque, foundWG bool
	for _, o := range out.Outbounds {
		if o.Tag == WarpMasqueTag {
			foundMasque = true
		}
	}
	for _, e := range out.Endpoints {
		if e.Tag == WarpWGTag {
			foundWG = true
		}
	}
	if !foundMasque || !foundWG {
		t.Fatalf("dedicated WARP leaves stripped: masque=%v wg=%v", foundMasque, foundWG)
	}
}

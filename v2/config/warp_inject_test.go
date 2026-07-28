package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestSetOutboundsInjectsWarp(t *testing.T) {
	opt := DefaultHiddifyOptions()
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

	var foundMasque, foundWG bool
	for _, o := range out.Outbounds {
		if o.Tag == WarpMasqueTag {
			foundMasque = true
		}
		if o.Tag == "node1" {
			opts := o.Options.(*option.VLESSOutboundOptions)
			if opts.Detour != "" {
				t.Fatalf("node1 should not have detour without chain, got %q", opts.Detour)
			}
		}
	}
	for _, e := range out.Endpoints {
		if e.Tag == WarpWGTag {
			foundWG = true
		}
	}
	if !foundMasque || !foundWG {
		t.Fatalf("masque=%v wg=%v", foundMasque, foundWG)
	}
}

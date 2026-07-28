package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestChainDetourOnMembers(t *testing.T) {
	opt := DefaultHiddifyOptions()
	opt.Chain = ChainOptions{
		DetourTarget:  "relay",
		DetourMembers: []string{"node-a", "node-b"},
	}
	input := &option.Options{
		Outbounds: []option.Outbound{
			{
				Type: C.TypeVLESS,
				Tag:  "relay",
				Options: &option.VLESSOutboundOptions{
					DialerOptions: option.DialerOptions{},
				},
			},
			{
				Type: C.TypeVLESS,
				Tag:  "node-a",
				Options: &option.VLESSOutboundOptions{
					DialerOptions: option.DialerOptions{},
				},
			},
			{
				Type: C.TypeVLESS,
				Tag:  "node-b",
				Options: &option.VLESSOutboundOptions{
					DialerOptions: option.DialerOptions{},
				},
			},
			{
				Type: C.TypeVLESS,
				Tag:  "node-c",
				Options: &option.VLESSOutboundOptions{
					DialerOptions: option.DialerOptions{},
				},
			},
		},
	}
	var out option.Options
	if err := setOutbounds(&out, input, opt, &map[string][]string{}); err != nil {
		t.Fatal(err)
	}
	for _, o := range out.Outbounds {
		switch o.Tag {
		case "relay", "node-a", "node-b", "node-c":
			opts, ok := o.Options.(*option.VLESSOutboundOptions)
			if !ok {
				t.Fatalf("%s: expected vless options", o.Tag)
			}
			switch o.Tag {
			case "relay":
				if opts.Detour != "" {
					t.Fatalf("relay detour=%q want empty", opts.Detour)
				}
			case "node-a", "node-b":
				if opts.Detour != "relay" {
					t.Fatalf("%s detour=%q want relay", o.Tag, opts.Detour)
				}
			case "node-c":
				if opts.Detour != "" {
					t.Fatalf("node-c detour=%q want empty", opts.Detour)
				}
			}
		}
	}
}

func TestChainDetourEmptyTarget(t *testing.T) {
	opt := DefaultHiddifyOptions()
	opt.Chain = ChainOptions{
		DetourTarget:  "",
		DetourMembers: []string{"node-a"},
	}
	input := &option.Options{
		Outbounds: []option.Outbound{{
			Type: C.TypeVLESS,
			Tag:  "node-a",
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
		if o.Tag != "node-a" {
			continue
		}
		opts, ok := o.Options.(*option.VLESSOutboundOptions)
		if !ok {
			t.Fatal("node-a: expected vless options")
		}
		if opts.Detour != "" {
			t.Fatalf("detour=%q want empty", opts.Detour)
		}
		return
	}
	t.Fatal("node-a not found in outbounds")
}

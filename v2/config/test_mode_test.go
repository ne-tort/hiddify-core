package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestTestModeOmitsBalancers(t *testing.T) {
	opt := DefaultClientOptions()
	opt.TestMode = true
	input := &option.Options{
		Outbounds: []option.Outbound{
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
		},
	}
	var out option.Options
	if err := setOutbounds(&out, input, opt, &map[string][]string{}); err != nil {
		t.Fatal(err)
	}
	for _, o := range out.Outbounds {
		if o.Tag == OutboundURLTestTag || o.Tag == OutboundRoundRobinTag {
			t.Fatalf("TestMode must omit balancer %q", o.Tag)
		}
		if o.Tag != OutboundSelectTag {
			continue
		}
		sel, ok := o.Options.(*option.SelectorOutboundOptions)
		if !ok {
			t.Fatal("select: expected SelectorOutboundOptions")
		}
		if len(sel.Outbounds) != 2 {
			t.Fatalf("select outbounds=%v want [node-a node-b]", sel.Outbounds)
		}
		for _, tag := range sel.Outbounds {
			if tag == OutboundURLTestTag || tag == OutboundRoundRobinTag {
				t.Fatalf("select must not reference balancer %q", tag)
			}
		}
	}
}

func TestTestModeSlimOutboundTag(t *testing.T) {
	opt := DefaultClientOptions()
	opt.TestMode = true
	opt.TestOutboundTag = "node-b"
	input := &option.Options{
		Outbounds: []option.Outbound{
			{Type: C.TypeVLESS, Tag: "node-a", Options: &option.VLESSOutboundOptions{}},
			{Type: C.TypeVLESS, Tag: "node-b", Options: &option.VLESSOutboundOptions{}},
		},
	}
	var out option.Options
	if err := setOutbounds(&out, input, opt, &map[string][]string{}); err != nil {
		t.Fatal(err)
	}
	for _, o := range out.Outbounds {
		if o.Tag != OutboundSelectTag {
			continue
		}
		sel := o.Options.(*option.SelectorOutboundOptions)
		if len(sel.Outbounds) != 1 || sel.Outbounds[0] != "node-b" {
			t.Fatalf("select outbounds=%v want [node-b]", sel.Outbounds)
		}
	}
}

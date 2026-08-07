package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestDisabledOutboundExcludedFromBalancer(t *testing.T) {
	opt := DefaultClientOptions()
	opt.DisabledOutboundTags = []string{"node-b"}
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
		if o.Tag != OutboundRoundRobinTag && o.Tag != OutboundURLTestTag {
			continue
		}
		opts, ok := o.Options.(*option.BalancerOutboundOptions)
		if !ok {
			t.Fatalf("%s: expected balancer options", o.Tag)
		}
		for _, tag := range opts.Outbounds {
			if tag == "node-b" {
				t.Fatalf("%s includes disabled tag node-b", o.Tag)
			}
		}
		if len(opts.Outbounds) != 1 || opts.Outbounds[0] != "node-a" {
			t.Fatalf("%s outbounds=%v want [node-a]", o.Tag, opts.Outbounds)
		}
	}
}

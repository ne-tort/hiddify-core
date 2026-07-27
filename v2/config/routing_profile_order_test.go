package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
)

func TestCompileRoutingProfileOrder(t *testing.T) {
	p := &RoutingProfile{
		Enabled:     true,
		GlobalProxy: true,
		RuleOrder:   "proxy-direct-block",
		DirectSites: []string{"example.com"},
		ProxySites:  []string{"proxy.example"},
		BlockSites:  []string{"ads.example"},
	}
	_, rules := CompileRoutingProfile(p, "", "")
	if len(rules) < 3 {
		t.Fatalf("rules=%d", len(rules))
	}
	// First should be proxy (route to select), then direct, then reject.
	if rules[0].DefaultOptions.RuleAction.Action != C.RuleActionTypeRoute {
		t.Fatalf("first action=%s", rules[0].DefaultOptions.RuleAction.Action)
	}
	if rules[0].DefaultOptions.RuleAction.RouteOptions.Outbound != OutboundSelectTag {
		t.Fatalf("first outbound=%s", rules[0].DefaultOptions.RuleAction.RouteOptions.Outbound)
	}
	if rules[2].DefaultOptions.RuleAction.Action != C.RuleActionTypeReject {
		t.Fatalf("third action=%s", rules[2].DefaultOptions.RuleAction.Action)
	}
}

func TestCompileRoutingProfileRemoteSrs(t *testing.T) {
	p := &RoutingProfile{
		Enabled:     true,
		DirectSites: []string{"remote-srs:https://example.com/custom.srs"},
	}
	rs, rules := CompileRoutingProfile(p, "", "")
	if len(rs) != 1 || rs[0].Type != C.RuleSetTypeRemote {
		t.Fatalf("rulesets=%+v", rs)
	}
	if len(rules) != 1 {
		t.Fatalf("rules=%d", len(rules))
	}
}

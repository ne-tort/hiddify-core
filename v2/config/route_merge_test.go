package config_test

import (
	"testing"

	"github.com/hiddify/hiddify-core/v2/config"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestBuildMergesSubscriptionRuleSet(t *testing.T) {
	profile := `{
  "outbounds": [
    {"type":"direct","tag":"node-a"}
  ],
  "route": {
    "rule_set": [
      {
        "type": "remote",
        "tag": "geoip-ru",
        "format": "binary",
        "url": "https://example.com/geoip/ru.srs"
      }
    ],
    "rules": [
      {
        "action": "route",
        "outbound": "direct",
        "rule_set": ["geoip-ru"]
      }
    ]
  }
}`
	h := config.DefaultHiddifyOptions()
	h.IgnoreSubscriptionRoute = false
	built, err := config.BuildConfig(testCtx(), h, &config.ReadOptions{Content: profile})
	if err != nil {
		t.Fatal(err)
	}
	if built.Route == nil {
		t.Fatal("nil route")
	}
	foundRS := false
	for _, rs := range built.Route.RuleSet {
		if rs.Tag == "geoip-ru" {
			foundRS = true
			if rs.Type != C.RuleSetTypeRemote {
				t.Fatalf("type=%s", rs.Type)
			}
			if rs.RemoteOptions.URL != "https://example.com/geoip/ru.srs" {
				t.Fatalf("url=%s", rs.RemoteOptions.URL)
			}
		}
	}
	if !foundRS {
		t.Fatal("expected geoip-ru rule_set in built route")
	}
	foundRule := false
	for _, rule := range built.Route.Rules {
		if rule.Type != "" && rule.Type != C.RuleTypeDefault {
			continue
		}
		r := rule.DefaultOptions
		for _, tag := range r.RuleSet {
			if tag == "geoip-ru" {
				foundRule = true
				if r.Action != C.RuleActionTypeRoute {
					t.Fatalf("action=%s", r.Action)
				}
				if r.RouteOptions.Outbound != config.OutboundDirectTag {
					t.Fatalf("outbound=%s want %s", r.RouteOptions.Outbound, config.OutboundDirectTag)
				}
			}
		}
	}
	if !foundRule {
		t.Fatal("expected rule referencing geoip-ru with remapped direct")
	}
}

func TestBuildIgnoresSubscriptionRouteWhenFlagged(t *testing.T) {
	profile := `{
  "outbounds": [{"type":"direct","tag":"node-a"}],
  "route": {
    "rule_set": [{"type":"remote","tag":"geoip-ru","format":"binary","url":"https://example.com/ru.srs"}],
    "rules": [{"action":"route","outbound":"direct","rule_set":["geoip-ru"]}]
  }
}`
	h := config.DefaultHiddifyOptions()
	h.IgnoreSubscriptionRoute = true
	built, err := config.BuildConfig(testCtx(), h, &config.ReadOptions{Content: profile})
	if err != nil {
		t.Fatal(err)
	}
	for _, rs := range built.Route.RuleSet {
		if rs.Tag == "geoip-ru" {
			t.Fatal("subscription rule_set should be ignored")
		}
	}
}

func TestCompileRoutingProfile(t *testing.T) {
	p := &config.RoutingProfile{
		Name:        "RU",
		Enabled:     true,
		GlobalProxy: true,
		DirectIP:    []string{"geoip:ru"},
		BlockSites:  []string{"geosite:category-ads-all"},
	}
	rs, rules := config.CompileRoutingProfile(p, "", "")
	if len(rs) < 2 {
		t.Fatalf("want >=2 rule_sets, got %d", len(rs))
	}
	tags := map[string]bool{}
	for _, r := range rs {
		tags[r.Tag] = true
	}
	if !tags["geoip-ru"] || !tags["geosite-category-ads-all"] {
		t.Fatalf("tags=%v", tags)
	}
	if len(rules) < 2 {
		t.Fatalf("want rules, got %d", len(rules))
	}
	// first rules should include reject for ads
	hasReject := false
	hasDirect := false
	for _, rule := range rules {
		r := rule.DefaultOptions
		if r.Action == C.RuleActionTypeReject {
			hasReject = true
		}
		if r.Action == C.RuleActionTypeRoute && r.RouteOptions.Outbound == config.OutboundDirectTag {
			hasDirect = true
		}
	}
	if !hasReject || !hasDirect {
		t.Fatalf("reject=%v direct=%v", hasReject, hasDirect)
	}
}

func TestRemapLogicalOutbound(t *testing.T) {
	out, reject := config.RemapLogicalOutbound("direct")
	if reject || out != config.OutboundDirectTag {
		t.Fatalf("direct -> %s reject=%v", out, reject)
	}
	out, reject = config.RemapLogicalOutbound("block")
	if !reject || out != "" {
		t.Fatalf("block -> %s reject=%v", out, reject)
	}
	out, reject = config.RemapLogicalOutbound("proxy")
	if reject || out != config.OutboundSelectTag {
		t.Fatalf("proxy -> %s reject=%v", out, reject)
	}
}

func TestParseHappRoutingProfile(t *testing.T) {
	m := map[string]any{
		"Name":        "China",
		"GlobalProxy": "true",
		"DirectSites": []any{"geosite:cn"},
		"DirectIp":    []any{"geoip:cn"},
		"BlockSites":  []any{"geosite:category-ads-all"},
		"Geoipurl":    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
	}
	p, err := config.ParseHappRoutingProfile(m)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "China" || !p.GlobalProxy {
		t.Fatalf("%+v", p)
	}
	if len(p.DirectSites) != 1 || p.DirectSites[0] != "geosite:cn" {
		t.Fatalf("sites=%v", p.DirectSites)
	}
	if p.GeoIPURL != "" {
		t.Fatalf(".dat url should be cleared, got %s", p.GeoIPURL)
	}
}

func TestLocalProfileWinsOverSubscriptionOrder(t *testing.T) {
	// Local direct for geoip-ru, subscription would block same tag — local rule must appear first.
	profile := `{
  "outbounds": [{"type":"direct","tag":"node-a"}],
  "route": {
    "rule_set": [{"type":"remote","tag":"geoip-ru","format":"binary","url":"https://example.com/ru.srs"}],
    "rules": [{"action":"reject","rule_set":["geoip-ru"]}]
  }
}`
	h := config.DefaultHiddifyOptions()
	h.IgnoreSubscriptionRoute = false
	h.RoutePriority = config.RoutePrioritySubscriptionFirst // must be ignored
	h.RoutingProfile = &config.RoutingProfile{
		Name:        "local",
		Enabled:     true,
		GlobalProxy: true,
		DirectIP:    []string{"geoip:ru"},
	}
	built, err := config.BuildConfig(testCtx(), h, &config.ReadOptions{Content: profile})
	if err != nil {
		t.Fatal(err)
	}
	var firstGeoipAction string
	for _, rule := range built.Route.Rules {
		r := rule.DefaultOptions
		for _, tag := range r.RuleSet {
			if tag == "geoip-ru" {
				firstGeoipAction = r.Action
				goto done
			}
		}
	}
done:
	if firstGeoipAction != C.RuleActionTypeRoute {
		t.Fatalf("first geoip-ru action=%q, want route (local direct before sub reject)", firstGeoipAction)
	}
}

func TestSubscriptionRouteHasPolicy(t *testing.T) {
	if config.SubscriptionRouteHasPolicy(nil) {
		t.Fatal("nil")
	}
	if config.SubscriptionRouteHasPolicy(&option.RouteOptions{
		Rules: []option.Rule{{
			DefaultOptions: option.DefaultRule{
				RuleAction: option.RuleAction{Action: C.RuleActionTypeSniff},
			},
		}},
	}) {
		t.Fatal("bare sniff is not policy")
	}
	if !config.SubscriptionRouteHasPolicy(&option.RouteOptions{
		RuleSet: []option.RuleSet{{Tag: "geoip-ru"}},
	}) {
		t.Fatal("rule_set is policy")
	}
}

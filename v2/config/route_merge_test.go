package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hiddify/hiddify-core/v2/config"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func ruleSetTagContains(tags badoption.Listable[string], want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

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

	t.Run("failClosedWithoutFile", func(t *testing.T) {
		_, err := config.BuildConfig(testCtx(), h, &config.ReadOptions{Content: profile})
		if err == nil {
			t.Fatal("expected fail-closed error for remote rule_set without local file")
		}
	})

	t.Run("rewritesToLocalWhenFileExists", func(t *testing.T) {
		dir := t.TempDir()
		rulesDir := filepath.Join(dir, "rules")
		if err := os.MkdirAll(rulesDir, 0o755); err != nil {
			t.Fatal(err)
		}
		srs := filepath.Join(rulesDir, "geoip-ru.srs")
		if err := os.WriteFile(srs, []byte("fake"), 0o644); err != nil {
			t.Fatal(err)
		}
		wd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chdir(wd) })

		built, err := config.BuildConfig(testCtx(), h, &config.ReadOptions{Content: profile})
		if err != nil {
			t.Fatal(err)
		}
		if built.Route == nil {
			t.Fatal("nil route")
		}
		foundRS := false
		for _, rs := range built.Route.RuleSet {
			if ruleSetTagContains(rs.Tag, "geoip-ru") {
				foundRS = true
				if rs.Type != C.RuleSetTypeLocal {
					t.Fatalf("type=%s want local", rs.Type)
				}
				if rs.LocalOptions.Path == "" {
					t.Fatal("empty local path")
				}
			}
			if rs.Type == C.RuleSetTypeRemote {
				t.Fatalf("unexpected remote rule_set %+v", rs)
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
	})
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
		if ruleSetTagContains(rs.Tag, "geoip-ru") {
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
		for _, tag := range r.Tag {
			tags[tag] = true
		}
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

func TestCompileRoutingProfileProcessPathRegex(t *testing.T) {
	p := &config.RoutingProfile{
		Name:        "rx",
		Enabled:     true,
		GlobalProxy: true,
		DirectProcesses: []config.ProcessMatch{
			{PathRegex: `(.*)\\Steam\\(.*)`},
			{Path: `*\Discord\*`}, // simple pattern → regex
		},
	}
	_, rules := config.CompileRoutingProfile(p, "", "")
	if len(rules) < 1 {
		t.Fatalf("rules=%d", len(rules))
	}
	foundExactRx := false
	foundConverted := false
	for _, rule := range rules {
		r := rule.DefaultOptions.RawDefaultRule
		for _, rx := range r.ProcessPathRegex {
			if rx == `(.*)\\Steam\\(.*)` {
				foundExactRx = true
			}
			if strings.Contains(rx, "Discord") {
				foundConverted = true
			}
		}
		if len(r.ProcessPath) > 0 {
			t.Fatalf("simple * path should not stay as process_path: %v", r.ProcessPath)
		}
	}
	if !foundExactRx || !foundConverted {
		t.Fatalf("exactRx=%v converted=%v", foundExactRx, foundConverted)
	}
	if !config.ProfileNeedsFindProcess(p) {
		t.Fatal("expected FindProcess")
	}
}

func TestCompileRoutingProfileOwnerRules(t *testing.T) {
	p := &config.RoutingProfile{
		Name:           "owner",
		Enabled:        true,
		GlobalProxy:    true,
		DirectPackages: []string{"com.bank.app"},
		ProxyProcesses: []config.ProcessMatch{{Name: "chrome.exe"}, {Path: `C:\Games\game.exe`}},
		BlockSites:     []string{"geosite:category-ads-all"},
	}
	_, rules := config.CompileRoutingProfile(p, "", "")
	if len(rules) < 3 {
		t.Fatalf("want owner+domain rules, got %d", len(rules))
	}
	if !config.ProfileNeedsFindProcess(p) {
		t.Fatal("expected FindProcess")
	}
	foundPkg := false
	foundProcName := false
	foundProcPath := false
	for _, rule := range rules {
		r := rule.DefaultOptions.RawDefaultRule
		if len(r.PackageName) == 1 && r.PackageName[0] == "com.bank.app" {
			foundPkg = true
		}
		if len(r.ProcessName) == 1 && r.ProcessName[0] == "chrome.exe" {
			foundProcName = true
		}
		if len(r.ProcessPath) == 1 && r.ProcessPath[0] == `C:\Games\game.exe` {
			foundProcPath = true
		}
	}
	if !foundPkg || !foundProcName || !foundProcPath {
		t.Fatalf("pkg=%v name=%v path=%v", foundPkg, foundProcName, foundProcPath)
	}
}


func TestCompileRoutingProfileOwnerBeforeDomain(t *testing.T) {
	p := &config.RoutingProfile{
		Name:            "ord",
		Enabled:         true,
		GlobalProxy:     true,
		RuleOrder:       "proxy-direct-block",
		ProxyPackages:   []string{"com.proxy.app"},
		DirectSites:     []string{"example.com"},
		BlockProcesses:  []config.ProcessMatch{{Name: "torrent.exe"}},
	}
	_, rules := config.CompileRoutingProfile(p, "", "")
	if len(rules) < 3 {
		t.Fatalf("rules=%d", len(rules))
	}
	// Owner rules must precede domain/IP matchers.
	firstOwner := -1
	firstDomain := -1
	for i, rule := range rules {
		r := rule.DefaultOptions.RawDefaultRule
		if len(r.PackageName) > 0 || len(r.ProcessName) > 0 || len(r.ProcessPath) > 0 {
			if firstOwner < 0 {
				firstOwner = i
			}
		}
		if len(r.DomainSuffix) > 0 || len(r.IPCIDR) > 0 || len(r.RuleSet) > 0 {
			if firstDomain < 0 {
				firstDomain = i
			}
		}
	}
	if firstOwner < 0 || firstDomain < 0 {
		t.Fatalf("owner=%d domain=%d", firstOwner, firstDomain)
	}
	if firstOwner >= firstDomain {
		t.Fatalf("owner index %d should be before domain index %d", firstOwner, firstDomain)
	}
}

func TestBuildConfigFindProcessFromOwnerRules(t *testing.T) {
	profile := `{
  "outbounds": [{"type":"direct","tag":"node-a"}]
}`
	h := config.DefaultHiddifyOptions()
	h.IgnoreSubscriptionRoute = true
	h.RoutingProfiles = []*config.RoutingProfile{{
		Name:           "p",
		Enabled:        true,
		GlobalProxy:    true,
		DirectPackages: []string{"com.example"},
		ProxyProcesses: []config.ProcessMatch{{Name: "curl"}},
	}}
	built, err := config.BuildConfig(testCtx(), h, &config.ReadOptions{Content: profile})
	if err != nil {
		t.Fatal(err)
	}
	if built.Route == nil || !built.Route.FindProcess {
		t.Fatalf("FindProcess want true, route=%+v", built.Route)
	}
	foundPkg := false
	foundProc := false
	for _, rule := range built.Route.Rules {
		r := rule.DefaultOptions.RawDefaultRule
		if len(r.PackageName) > 0 && r.PackageName[0] == "com.example" {
			foundPkg = true
		}
		if len(r.ProcessName) > 0 && r.ProcessName[0] == "curl" {
			foundProc = true
		}
	}
	if !foundPkg || !foundProc {
		t.Fatalf("pkg=%v proc=%v", foundPkg, foundProc)
	}
}

func TestBuildConfigGlobalProxyFinalWithProcessOwner(t *testing.T) {
	profile := `{
  "outbounds": [{"type":"direct","tag":"node-a"}]
}`
	falseVal := false
	h := config.DefaultHiddifyOptions()
	h.IgnoreSubscriptionRoute = true
	h.RoutingGlobalProxy = &falseVal
	h.RoutingProfiles = []*config.RoutingProfile{{
		Name:           "p",
		Enabled:        true,
		ProxyProcesses: []config.ProcessMatch{{Name: "chrome.exe"}},
		DirectProcesses: []config.ProcessMatch{
			{Path: `C:\Program Files\Game\game.exe`},
		},
	}}
	built, err := config.BuildConfig(testCtx(), h, &config.ReadOptions{Content: profile})
	if err != nil {
		t.Fatal(err)
	}
	if built.Route == nil {
		t.Fatal("nil route")
	}
	// Unmatched traffic (incl. processes not listed) → direct when global proxy off.
	if built.Route.Final != config.OutboundDirectTag {
		t.Fatalf("final=%q want direct", built.Route.Final)
	}
	if !built.Route.FindProcess {
		t.Fatal("FindProcess required for process owner rules")
	}
	foundProxyName := false
	foundDirectPath := false
	for _, rule := range built.Route.Rules {
		r := rule.DefaultOptions
		raw := r.RawDefaultRule
		if len(raw.ProcessName) == 1 && raw.ProcessName[0] == "chrome.exe" {
			if r.Action == C.RuleActionTypeRoute && r.RouteOptions.Outbound == config.OutboundSelectTag {
				foundProxyName = true
			}
		}
		if len(raw.ProcessPath) == 1 && raw.ProcessPath[0] == `C:\Program Files\Game\game.exe` {
			if r.Action == C.RuleActionTypeRoute && r.RouteOptions.Outbound == config.OutboundDirectTag {
				foundDirectPath = true
			}
		}
	}
	if !foundProxyName || !foundDirectPath {
		t.Fatalf("proxyName=%v directPath=%v", foundProxyName, foundDirectPath)
	}
}

func TestCompileRoutingProfileStripsProcessQuotes(t *testing.T) {
	p := &config.RoutingProfile{
		Name:        "q",
		Enabled:     true,
		GlobalProxy: true,
		ProxyProcesses: []config.ProcessMatch{
			{Name: `"chrome.exe"`},
			{Path: `"C:\Program Files\app.exe"`},
			{PathRegex: `"(.*)\\Steam\\(.*)"`},
		},
	}
	_, rules := config.CompileRoutingProfile(p, "", "")
	foundName, foundPath, foundRx := false, false, false
	for _, rule := range rules {
		r := rule.DefaultOptions.RawDefaultRule
		for _, n := range r.ProcessName {
			if n == "chrome.exe" {
				foundName = true
			}
			if strings.Contains(n, `"`) {
				t.Fatalf("quoted name leaked: %q", n)
			}
		}
		for _, path := range r.ProcessPath {
			if path == `C:\Program Files\app.exe` {
				foundPath = true
			}
			if strings.Contains(path, `"`) {
				t.Fatalf("quoted path leaked: %q", path)
			}
		}
		for _, rx := range r.ProcessPathRegex {
			if rx == `(.*)\\Steam\\(.*)` {
				foundRx = true
			}
		}
	}
	if !foundName || !foundPath || !foundRx {
		t.Fatalf("name=%v path=%v rx=%v", foundName, foundPath, foundRx)
	}
}

func TestRoutingProfileOwnerJSONRoundtrip(t *testing.T) {
	raw := []byte(`{
  "name":"x","enabled":true,"global_proxy":true,
  "direct_packages":["com.a","com.a","  "],
  "proxy_processes":[{"name":"chrome.exe"},{"path":"/usr/bin/curl"},{"name":"","path":""}]
}`)
	var p config.RoutingProfile
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.DirectPackages) != 3 {
		t.Fatalf("raw packages=%v", p.DirectPackages)
	}
	_, rules := config.CompileRoutingProfile(&p, "", "")
	var pkgRule, pathRule, nameRule bool
	for _, rule := range rules {
		r := rule.DefaultOptions.RawDefaultRule
		if len(r.PackageName) == 1 && r.PackageName[0] == "com.a" {
			pkgRule = true
		}
		if len(r.ProcessName) == 1 && r.ProcessName[0] == "chrome.exe" {
			nameRule = true
		}
		if len(r.ProcessPath) == 1 && r.ProcessPath[0] == "/usr/bin/curl" {
			pathRule = true
		}
	}
	if !pkgRule || !pathRule || !nameRule {
		t.Fatalf("pkg=%v path=%v name=%v rules=%d", pkgRule, pathRule, nameRule, len(rules))
	}
	// Duplicate package collapsed by normalizeStringList.
	if !config.ProfileNeedsFindProcess(&p) {
		t.Fatal("need find_process")
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
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "geoip-ru.srs"), []byte("fake"), 0o644); err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	h := config.DefaultHiddifyOptions()
	h.IgnoreSubscriptionRoute = false
	h.RoutePriority = config.RoutePrioritySubscriptionFirst // must be ignored
	h.GeoIPRuleSetURL = filepath.Join("rules", "geoip-{tag}.srs")
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
	for _, rs := range built.Route.RuleSet {
		if rs.Type == C.RuleSetTypeRemote {
			t.Fatalf("unexpected remote %+v", rs)
		}
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
		RuleSet: []option.RuleSet{{Tag: []string{"geoip-ru"}}},
	}) {
		t.Fatal("rule_set is policy")
	}
}

package config

import (
	"os"
	"path/filepath"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestCompileRoutingProfilePathTemplateIsLocal(t *testing.T) {
	p := &RoutingProfile{
		Name:        "RU",
		Enabled:     true,
		GlobalProxy: true,
		DirectIP:    []string{"geoip:ru"},
	}
	rs, _ := CompileRoutingProfile(p, filepath.Join("rules", "geoip-{tag}.srs"), "")
	if len(rs) != 1 {
		t.Fatalf("rs=%d", len(rs))
	}
	if rs[0].Type != C.RuleSetTypeLocal {
		t.Fatalf("type=%s want local", rs[0].Type)
	}
	if rs[0].LocalOptions.Path == "" {
		t.Fatal("empty path")
	}
}

func TestSanitizeRuleSetsLocalOnly(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "tags", "cache")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cache, "custom.srs")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
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

	in := []option.RuleSet{{
		Type: C.RuleSetTypeRemote,
		Tag:  ruleSetTags("custom"),
		RemoteOptions: option.RemoteRuleSet{
			URL: "https://example.com/custom.srs",
		},
	}}
	out, err := sanitizeRuleSetsLocalOnly(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Type != C.RuleSetTypeLocal {
		t.Fatalf("out=%+v", out)
	}

	_, err = sanitizeRuleSetsLocalOnly([]option.RuleSet{{
		Type: C.RuleSetTypeRemote,
		Tag:  ruleSetTags("missing"),
		RemoteOptions: option.RemoteRuleSet{
			URL: "https://example.com/missing.srs",
		},
	}})
	if err == nil {
		t.Fatal("expected fail-closed error")
	}
}

func TestBuildConfigLocalSrsZeroRemote(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "merged.srs")
	if err := os.WriteFile(local, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile := `{"outbounds":[{"type":"direct","tag":"node-a"}]}`
	h := DefaultClientOptions()
	h.IgnoreSubscriptionRoute = true
	h.RoutingProfiles = []*RoutingProfile{{
		Name:        "p",
		Enabled:     true,
		GlobalProxy: true,
		DirectSites: []string{"local-srs:" + local},
	}}
	built, err := BuildConfig(testCtx(), h, &ReadOptions{Content: profile})
	if err != nil {
		t.Fatal(err)
	}
	for _, rs := range built.Route.RuleSet {
		if rs.Type == C.RuleSetTypeRemote {
			t.Fatalf("remote not allowed: %+v", rs)
		}
	}
}

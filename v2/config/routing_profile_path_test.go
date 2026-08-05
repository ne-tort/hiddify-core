package config

import (
	"path/filepath"
	"testing"
)

func TestNormalizeLocalRulesetPath(t *testing.T) {
	abs := `C:\data\hiddify_portable_data\routing_profiles\preset-ru\direct\merged.srs`
	got := normalizeLocalRulesetPath(abs)
	want := filepath.FromSlash("routing_profiles/preset-ru/direct/merged.srs")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}

	rel := `routing_profiles/preset-ru/direct/merged.srs`
	if normalizeLocalRulesetPath(rel) != filepath.FromSlash(rel) {
		t.Fatalf("relative path should stay unchanged")
	}

	ads := `C:\data\hiddify_portable_data\rules\hiddify-ads.srs`
	gotAds := normalizeLocalRulesetPath(ads)
	wantAds := filepath.FromSlash("rules/hiddify-ads.srs")
	if gotAds != wantAds {
		t.Fatalf("ads path got %q want %q", gotAds, wantAds)
	}
}

func TestCompileRoutingProfileLocalSrsRelative(t *testing.T) {
	p := &RoutingProfile{
		Enabled:     true,
		DirectSites: []string{`local-srs:C:\base\hiddify_portable_data\routing_profiles\preset-ru\direct\merged.srs`},
	}
	rs, rules := CompileRoutingProfile(p, "", "")
	if len(rs) != 1 {
		t.Fatalf("want 1 ruleset got %d", len(rs))
	}
	want := filepath.FromSlash("routing_profiles/preset-ru/direct/merged.srs")
	if rs[0].LocalOptions.Path != want {
		t.Fatalf("path %q want %q", rs[0].LocalOptions.Path, want)
	}
	if len(rules) != 1 {
		t.Fatalf("want 1 rule got %d", len(rules))
	}
}

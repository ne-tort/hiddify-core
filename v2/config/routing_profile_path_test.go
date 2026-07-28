package config

import (
	"path/filepath"
	"testing"
)

func TestNormalizeLocalRulesetPath(t *testing.T) {
	abs := `C:\data\hiddify_portable_data\routing_profiles\preset-ru\direct\merged.srs`
	got := normalizeLocalRulesetPath(abs)
	want := `routing_profiles\preset-ru\direct\merged.srs`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}

	rel := `routing_profiles/preset-ru/direct/merged.srs`
	if normalizeLocalRulesetPath(rel) != filepath.FromSlash(rel) {
		t.Fatalf("relative path should stay unchanged")
	}

	ads := `C:\data\hiddify_portable_data\rules\hiddify-ads.srs`
	gotAds := normalizeLocalRulesetPath(ads)
	if gotAds != `rules\hiddify-ads.srs` {
		t.Fatalf("ads path got %q", gotAds)
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
	if rs[0].LocalOptions.Path != `routing_profiles\preset-ru\direct\merged.srs` {
		t.Fatalf("path %q", rs[0].LocalOptions.Path)
	}
	if len(rules) != 1 {
		t.Fatalf("want 1 rule got %d", len(rules))
	}
}

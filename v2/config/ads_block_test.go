package config

import (
	"os"
	"path/filepath"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestAppendAdsBlockRules(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "hiddify-ads.srs")
	if err := os.WriteFile(path, []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}

	var rulesets []option.RuleSet
	var rules []option.Rule
	appendAdsBlockRules(&rulesets, &rules, path)

	if len(rulesets) != 1 {
		t.Fatalf("rulesets=%d", len(rulesets))
	}
	if rulesets[0].Tag != AdsRuleSetTag || rulesets[0].Type != C.RuleSetTypeLocal {
		t.Fatalf("ruleset tag/type")
	}
	if rulesets[0].LocalOptions.Path != path {
		t.Fatalf("path=%s", rulesets[0].LocalOptions.Path)
	}
	if len(rules) != 1 {
		t.Fatalf("rules=%d", len(rules))
	}
	if rules[0].DefaultOptions.RuleAction.Action != C.RuleActionTypeReject {
		t.Fatalf("action=%s", rules[0].DefaultOptions.RuleAction.Action)
	}
}

func TestAppendAdsBlockRulesEmptyPath(t *testing.T) {
	var rulesets []option.RuleSet
	var rules []option.Rule
	appendAdsBlockRules(&rulesets, &rules, "")
	if len(rulesets) != 0 || len(rules) != 0 {
		t.Fatal("expected no-op")
	}
}

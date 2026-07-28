package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestMergeLocalRuleSetsWritesValidVersion(t *testing.T) {
	dir := t.TempDir()
	srcJSON := filepath.Join(dir, "in.json")
	outSRS := filepath.Join(dir, "out.srs")
	payload := []byte(`{"version":1,"rules":[{"domain_suffix":["example.com"]}]}`)
	if err := os.WriteFile(srcJSON, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := MergeLocalRuleSets([]string{srcJSON}, outSRS); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(outSRS)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	compat, err := srs.Read(f, false)
	if err != nil {
		t.Fatal(err)
	}
	if compat.Version < C.RuleSetVersion1 || compat.Version > C.RuleSetVersionCurrent {
		t.Fatalf("version=%d", compat.Version)
	}
	plain, err := compat.Upgrade()
	if err != nil {
		t.Fatal(err)
	}
	if len(plain.Rules) != 1 {
		t.Fatalf("rules=%d", len(plain.Rules))
	}
	_ = option.PlainRuleSet{}
}

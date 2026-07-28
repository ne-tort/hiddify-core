package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// MergeLocalRuleSets merges sing-box rule-set files (binary .srs or source .json)
// into a single binary .srs at outputPath.
func MergeLocalRuleSets(inputPaths []string, outputPath string) error {
	if len(inputPaths) == 0 {
		return fmt.Errorf("merge rulesets: no inputs")
	}
	if strings.TrimSpace(outputPath) == "" {
		return fmt.Errorf("merge rulesets: missing output path")
	}

	var merged option.PlainRuleSet
	var haveRules bool

	for _, rawPath := range inputPaths {
		path := strings.TrimSpace(rawPath)
		if path == "" {
			continue
		}
		plain, err := readPlainRuleSet(path)
		if err != nil {
			return err
		}
		if len(plain.Rules) > 0 {
			merged.Rules = append(merged.Rules, plain.Rules...)
			haveRules = true
		}
	}

	if !haveRules {
		return fmt.Errorf("merge rulesets: no rules found")
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()
	// Version 0 is invalid; SagerNet geosite/geoip ship as v1. Use current.
	if err := srs.Write(out, merged, C.RuleSetVersionCurrent); err != nil {
		return fmt.Errorf("merge rulesets: write %s: %w", outputPath, err)
	}
	return nil
}

func readPlainRuleSet(path string) (option.PlainRuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return option.PlainRuleSet{}, fmt.Errorf("merge rulesets: open %s: %w", path, err)
	}
	if len(data) >= 3 && data[0] == srs.MagicBytes[0] && data[1] == srs.MagicBytes[1] && data[2] == srs.MagicBytes[2] {
		f, err := os.Open(path)
		if err != nil {
			return option.PlainRuleSet{}, fmt.Errorf("merge rulesets: open %s: %w", path, err)
		}
		compat, err := srs.Read(f, true)
		_ = f.Close()
		if err != nil {
			return option.PlainRuleSet{}, fmt.Errorf("merge rulesets: read %s: %w", path, err)
		}
		plain, err := compat.Upgrade()
		if err != nil {
			return option.PlainRuleSet{}, fmt.Errorf("merge rulesets: upgrade %s: %w", path, err)
		}
		return plain, nil
	}

	var compat option.PlainRuleSetCompat
	if err := json.Unmarshal(data, &compat); err != nil {
		return option.PlainRuleSet{}, fmt.Errorf("merge rulesets: parse source %s: %w", path, err)
	}
	plain, err := compat.Upgrade()
	if err != nil {
		return option.PlainRuleSet{}, fmt.Errorf("merge rulesets: upgrade source %s: %w", path, err)
	}
	return plain, nil
}

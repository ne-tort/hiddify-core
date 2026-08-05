package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// isRemoteRulesetURL reports http(s) rule-set sources.
func isRemoteRulesetURL(url string) bool {
	lower := strings.ToLower(strings.TrimSpace(url))
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// resolveLocalRuleSetFile returns an existing local path for a rule-set tag / URL.
func resolveLocalRuleSetFile(tag, remoteURL string) string {
	candidates := make([]string, 0, 8)
	if remoteURL != "" && !isRemoteRulesetURL(remoteURL) {
		path := normalizeLocalRulesetPath(strings.TrimPrefix(strings.TrimSpace(remoteURL), "file://"))
		if path != "" {
			candidates = append(candidates, path)
		}
	}
	if tag != "" {
		candidates = append(candidates,
			filepath.Join("tags", "cache", tag+".srs"),
			filepath.Join("rules", tag+".srs"),
			tag+".srs",
		)
	}
	if isRemoteRulesetURL(remoteURL) {
		base := filepath.Base(strings.SplitN(remoteURL, "?", 2)[0])
		if strings.HasSuffix(strings.ToLower(base), ".srs") || strings.HasSuffix(strings.ToLower(base), ".json") {
			candidates = append(candidates,
				filepath.Join("tags", "cache", base),
				filepath.Join("rules", base),
				base,
			)
		}
	}
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return normalizeLocalRulesetPath(c)
		}
	}
	return ""
}

func localRuleSetFromPath(tag, path string) option.RuleSet {
	return option.RuleSet{
		Type:   C.RuleSetTypeLocal,
		Tag:    ruleSetTags(tag),
		Format: localRuleSetFormatByPath(path),
		LocalOptions: option.LocalRuleSet{
			Path: path,
		},
	}
}

// sanitizeRuleSetsLocalOnly rewrites remote rule_sets to local when a file exists,
// and fails closed when a remote entry cannot be materialized.
func sanitizeRuleSetsLocalOnly(rulesets []option.RuleSet) ([]option.RuleSet, error) {
	out := make([]option.RuleSet, 0, len(rulesets))
	for _, rs := range rulesets {
		if rs.Type != C.RuleSetTypeRemote {
			out = append(out, rs)
			continue
		}
		tag := ""
		if len(rs.Tag) > 0 {
			tag = rs.Tag[0]
		}
		path := resolveLocalRuleSetFile(tag, rs.RemoteOptions.URL)
		if path == "" {
			return nil, fmt.Errorf("fail-closed rule_set %q: remote source has no local file (url=%s)", tag, rs.RemoteOptions.URL)
		}
		out = append(out, localRuleSetFromPath(tag, path))
	}
	return out, nil
}

package config

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

const AdsRuleSetTag = "pathology-ads"

// appendAdsBlockRules prepends a local ads rule-set and reject rule (L4, before profile buckets).
func appendAdsBlockRules(rulesets *[]option.RuleSet, rules *[]option.Rule, path string) {
	path = normalizeLocalRulesetPath(path)
	if path == "" {
		return
	}
	*rulesets = append(*rulesets, option.RuleSet{
		Type:   C.RuleSetTypeLocal,
		Tag:    ruleSetTags(AdsRuleSetTag),
		Format: C.RuleSetFormatBinary,
		LocalOptions: option.LocalRuleSet{
			Path: path,
		},
	})
	*rules = append(*rules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				RuleSet: []string{AdsRuleSetTag},
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeReject,
				RejectOptions: option.RejectActionOptions{
					Method: C.RuleActionRejectMethodDefault,
				},
			},
		},
	})
}

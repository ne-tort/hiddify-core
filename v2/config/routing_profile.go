package config

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// Default remote .srs templates (SagerNet rule-set branches).
const (
	DefaultGeoIPRuleSetURL   = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{tag}.srs"
	DefaultGeoSiteRuleSetURL = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{tag}.srs"
)

// RoutePriority is retained for JSON compat; Build always applies local profile
// before subscription route (client owns conflicts).
type RoutePriority string

const (
	RoutePriorityLocalFirst        RoutePriority = "local"
	RoutePrioritySubscriptionFirst RoutePriority = "subscription" // ignored; kept for older clients
)

// RoutingProfile is the Happ-like canonical routing model (client + optional panel).
type RoutingProfile struct {
	Name        string `json:"name,omitempty"`
	Enabled     bool   `json:"enabled,omitempty"`
	GlobalProxy bool   `json:"global_proxy,omitempty"` // final = proxy when true
	// RuleOrder: e.g. "block-direct-proxy" (default). Controls bucket emission order.
	RuleOrder string `json:"rule_order,omitempty"`

	DirectSites []string `json:"direct_sites,omitempty"`
	DirectIP    []string `json:"direct_ip,omitempty"`
	ProxySites  []string `json:"proxy_sites,omitempty"`
	ProxyIP     []string `json:"proxy_ip,omitempty"`
	BlockSites  []string `json:"block_sites,omitempty"`
	BlockIP     []string `json:"block_ip,omitempty"`

	// Asset templates; `{tag}` replaced with country/category code (without geoip:/geosite: prefix).
	GeoIPURL   string `json:"geoip_url,omitempty"`
	GeoSiteURL string `json:"geosite_url,omitempty"`
}

// RoutingProfileOptions are client settings for profile merge.
type RoutingProfileOptions struct {
	IgnoreSubscriptionRoute bool             `json:"ignore-subscription-route,omitempty"`
	RoutePriority           RoutePriority    `json:"route-priority,omitempty"`
	Profile                 *RoutingProfile  `json:"routing-profile,omitempty"`
	GeoIPURL                string           `json:"geoip-ruleset-url,omitempty"`
	GeoSiteURL              string           `json:"geosite-ruleset-url,omitempty"`
}

// CompileRoutingProfile builds rule_sets + rules from an abstract profile.
func CompileRoutingProfile(p *RoutingProfile, geoIPURL, geoSiteURL string) (rulesets []option.RuleSet, rules []option.Rule) {
	if p == nil || !p.Enabled {
		return nil, nil
	}
	if geoIPURL == "" {
		geoIPURL = p.GeoIPURL
	}
	if geoSiteURL == "" {
		geoSiteURL = p.GeoSiteURL
	}
	if geoIPURL == "" {
		geoIPURL = DefaultGeoIPRuleSetURL
	}
	if geoSiteURL == "" {
		geoSiteURL = DefaultGeoSiteRuleSetURL
	}

	seen := map[string]struct{}{}
	addRS := func(tag, url string) {
		if tag == "" {
			return
		}
		if _, ok := seen[tag]; ok {
			return
		}
		seen[tag] = struct{}{}
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    tag,
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            url,
				UpdateInterval: badoption.Duration(24 * time.Hour),
				DownloadDetour: OutboundDirectTag,
			},
		})
	}
	addLocalRS := func(tag, path string) {
		if tag == "" || path == "" {
			return
		}
		if _, ok := seen[tag]; ok {
			return
		}
		seen[tag] = struct{}{}
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeLocal,
			Tag:    tag,
			Format: C.RuleSetFormatBinary,
			LocalOptions: option.LocalRuleSet{
				Path: path,
			},
		})
	}

	var blockRS, directRS, proxyRS []string
	var blockDomain, directDomain, proxyDomain []string
	var blockCIDR, directCIDR, proxyCIDR []string

	consume := func(items []string, rs *[]string, domains *[]string, cidrs *[]string) {
		for _, raw := range items {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			lower := strings.ToLower(raw)
			switch {
			case strings.HasPrefix(lower, "geoip:"):
				code := strings.TrimPrefix(lower, "geoip:")
				tag := "geoip-" + code
				addRS(tag, strings.ReplaceAll(geoIPURL, "{tag}", code))
				*rs = append(*rs, tag)
			case strings.HasPrefix(lower, "geosite:"):
				code := strings.TrimPrefix(lower, "geosite:")
				tag := "geosite-" + code
				addRS(tag, strings.ReplaceAll(geoSiteURL, "{tag}", code))
				*rs = append(*rs, tag)
			case strings.HasPrefix(lower, "remote-srs:"):
				url := strings.TrimSpace(raw[len("remote-srs:"):])
				if url == "" {
					continue
				}
				tag := "custom-" + shortHash(url)
				addRS(tag, url)
				*rs = append(*rs, tag)
			case strings.HasPrefix(lower, "local-srs:"):
				path := strings.TrimSpace(raw[len("local-srs:"):])
				if path == "" {
					continue
				}
				tag := "local-" + shortHash(path)
				addLocalRS(tag, path)
				*rs = append(*rs, tag)
			default:
				if isCIDR(raw) {
					*cidrs = append(*cidrs, raw)
				} else {
					*domains = append(*domains, raw)
				}
			}
		}
	}

	consume(p.BlockSites, &blockRS, &blockDomain, &blockCIDR)
	consume(p.BlockIP, &blockRS, &blockDomain, &blockCIDR)
	consume(p.DirectSites, &directRS, &directDomain, &directCIDR)
	consume(p.DirectIP, &directRS, &directDomain, &directCIDR)
	consume(p.ProxySites, &proxyRS, &proxyDomain, &proxyCIDR)
	consume(p.ProxyIP, &proxyRS, &proxyDomain, &proxyCIDR)

	appendMatchRules := func(rsTags, domains, cidrs []string, reject bool, outbound string) {
		if len(rsTags) > 0 {
			rules = append(rules, matchRule(rsTags, nil, nil, reject, outbound))
		}
		if len(domains) > 0 {
			rules = append(rules, matchRule(nil, domains, nil, reject, outbound))
		}
		if len(cidrs) > 0 {
			rules = append(rules, matchRule(nil, nil, cidrs, reject, outbound))
		}
	}

	emits := map[string]func(){
		"block":  func() { appendMatchRules(blockRS, blockDomain, blockCIDR, true, "") },
		"direct": func() { appendMatchRules(directRS, directDomain, directCIDR, false, OutboundDirectTag) },
		"proxy":  func() { appendMatchRules(proxyRS, proxyDomain, proxyCIDR, false, OutboundSelectTag) },
	}
	order := strings.Split(p.RuleOrder, "-")
	if len(order) != 3 {
		order = []string{"block", "direct", "proxy"}
	}
	seenOrder := map[string]struct{}{}
	for _, name := range order {
		name = strings.ToLower(strings.TrimSpace(name))
		fn, ok := emits[name]
		if !ok {
			continue
		}
		if _, dup := seenOrder[name]; dup {
			continue
		}
		seenOrder[name] = struct{}{}
		fn()
	}
	for _, name := range []string{"block", "direct", "proxy"} {
		if _, ok := seenOrder[name]; !ok {
			emits[name]()
		}
	}

	return rulesets, rules
}

func shortHash(s string) string {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return fmt.Sprintf("%08x", h)
}

func matchRule(rsTags, domains, cidrs []string, reject bool, outbound string) option.Rule {
	raw := option.RawDefaultRule{}
	if len(rsTags) > 0 {
		raw.RuleSet = rsTags
	}
	if len(domains) > 0 {
		raw.DomainSuffix = domains
	}
	if len(cidrs) > 0 {
		raw.IPCIDR = cidrs
	}
	action := option.RuleAction{Action: C.RuleActionTypeRoute}
	if reject {
		action = option.RuleAction{
			Action: C.RuleActionTypeReject,
			RejectOptions: option.RejectActionOptions{
				Method: C.RuleActionRejectMethodDefault,
			},
		}
	} else {
		action.RouteOptions.Outbound = outbound
	}
	return option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: raw,
			RuleAction:     action,
		},
	}
}

func isCIDR(s string) bool {
	if strings.Contains(s, "/") {
		_, err := netip.ParsePrefix(s)
		return err == nil
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// ParseHappRoutingProfile imports Happ-compatible JSON fields into RoutingProfile.
func ParseHappRoutingProfile(m map[string]any) (*RoutingProfile, error) {
	if m == nil {
		return nil, fmt.Errorf("empty happ profile")
	}
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				switch t := v.(type) {
				case string:
					return t
				}
			}
		}
		return ""
	}
	boolish := func(keys ...string) bool {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				switch t := v.(type) {
				case bool:
					return t
				case string:
					return strings.EqualFold(t, "true") || t == "1"
				}
			}
		}
		return false
	}
	list := func(keys ...string) []string {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				switch t := v.(type) {
				case []any:
					out := make([]string, 0, len(t))
					for _, e := range t {
						if s, ok := e.(string); ok && s != "" {
							out = append(out, s)
						}
					}
					return out
				case []string:
					return t
				}
			}
		}
		return nil
	}

	p := &RoutingProfile{
		Name:        str("Name", "name"),
		Enabled:     true,
		GlobalProxy: boolish("GlobalProxy", "global_proxy"),
		RuleOrder:   str("rule_order", "RuleOrder"),
		DirectSites: list("DirectSites", "direct_sites"),
		DirectIP:    list("DirectIp", "direct_ip"),
		ProxySites:  list("ProxySites", "proxy_sites"),
		ProxyIP:     list("ProxyIp", "proxy_ip"),
		BlockSites:  list("BlockSites", "block_sites"),
		BlockIP:     list("BlockIp", "block_ip"),
		GeoIPURL:    str("Geoipurl", "geoip_url"),
		GeoSiteURL:  str("Geositeurl", "geosite_url"),
	}
	// Happ Geoipurl points at .dat — ignore for sing-box remote .srs templates.
	if strings.Contains(strings.ToLower(p.GeoIPURL), ".dat") {
		p.GeoIPURL = ""
	}
	if strings.Contains(strings.ToLower(p.GeoSiteURL), ".dat") {
		p.GeoSiteURL = ""
	}
	return p, nil
}

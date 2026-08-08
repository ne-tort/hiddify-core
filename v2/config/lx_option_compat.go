package config

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// ruleSetTags adapts a single tag to lx RuleSet.Tag (Listable[string]).
func ruleSetTags(tag string) badoption.Listable[string] {
	return badoption.Listable[string]{tag}
}

// dnsRouteAction builds DNS route action options for current lx API
// (RewriteTTL/DisableCache live on AbstractDNSRouteActionOptions).
//
// Do not set Strategy when the same DNS config uses query_type / ip_version
// (e.g. FakeDNS): sing-box 1.14 rejects Legacy strategy + query_type together.
// Prefer top-level dns.strategy or DomainResolveOptions.Strategy instead.
func dnsRouteAction(server string, strategy option.DomainStrategy, rewriteTTL *uint32, disableCache bool) option.DNSRouteActionOptions {
	return option.DNSRouteActionOptions{
		Server: server,
		AbstractDNSRouteActionOptions: option.AbstractDNSRouteActionOptions{
			Strategy:     strategy,
			RewriteTTL:   rewriteTTL,
			DisableCache: disableCache,
		},
	}
}

// dnsRouteWithOptionalStrategy omits Legacy rule-action strategy when FakeDNS
// (query_type rules) is enabled; callers should set dns.strategy instead.
func dnsRouteWithOptionalStrategy(server string, strategy option.DomainStrategy, fakeDNS bool, rewriteTTL *uint32, disableCache bool) option.DNSRouteActionOptions {
	if fakeDNS {
		strategy = 0
	}
	return dnsRouteAction(server, strategy, rewriteTTL, disableCache)
}

// dialerWithResolver builds DialerOptions with domain_resolver for current lx API
// (DomainResolver lives on AbstractDialerOptions).
func dialerWithResolver(detour, resolver string, strategy option.DomainStrategy) option.DialerOptions {
	d := option.DialerOptions{Detour: detour}
	if resolver != "" {
		d.AbstractDialerOptions = option.AbstractDialerOptions{
			DomainResolver: &option.DomainResolveOptions{
				Server:   resolver,
				Strategy: strategy,
			},
		}
	}
	return d
}

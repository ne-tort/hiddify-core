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
// (Strategy/RewriteTTL/DisableCache live on AbstractDNSRouteActionOptions).
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

package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	// dnscode "github.com/miekg/dns"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
)

var DnsDirectTags = []string{
	DNSStaticTag,
	DNSBootstrapTag,
	DNSLocalTag,
}
var DnsRemoteTags = []string{
	DNSRemoteTag,
}

var DEFAULT_DNS_TTL = uint32(60 * 60 * 24)

func getDnsAddress(d string) string {
	d = strings.TrimSpace(d)
	lower := strings.ToLower(d)
	// Preserve special schemes; never turn "local" into udp://local.
	switch lower {
	case "local", "fakeip":
		return lower
	}
	if strings.HasPrefix(lower, "local://") || strings.HasPrefix(lower, "fakeip://") || strings.HasPrefix(lower, "dhcp://") {
		return d
	}
	if !strings.Contains(d, "://") {
		return "udp://" + d
	}
	return d
}

// setDns builds the simple/advanced client DNS template (L2 when subscription has no dns
// or IgnoreSubscriptionDNS is set). Bootstrap has no detour (resolves outbound servers);
// remote uses OutboundMainDetour for app DNS. Both resolve via DNS groups (type: group).
func setDns(options *option.Options, opt *ClientOptions, staticIps *map[string][]string) error {
	return setDnsWithRemoteDetour(options, opt, staticIps, OutboundMainDetour)
}

// BuildDnsFragment builds a standalone dns object (for controlplane server PUT).
// remoteDetour defaults to "direct" when empty (server dataplane has no select outbound).
func BuildDnsFragment(options *option.Options, opt *ClientOptions, remoteDetour string) error {
	if strings.TrimSpace(remoteDetour) == "" {
		remoteDetour = "direct"
	}
	return setDnsWithRemoteDetour(options, opt, nil, remoteDetour)
}

func setDnsWithRemoteDetour(options *option.Options, opt *ClientOptions, staticIps *map[string][]string, remoteDetour string) error {
	directServers := resolveDnsServerList(opt.DirectDnsServers, "udp://1.1.1.1")
	remoteServers := resolveDnsServerList(opt.RemoteDnsServers, "local")

	local, err := getDNSServerOptions(DNSLocalTag, "local", "", "")
	if err != nil {
		return err
	}

	bootstrapMembers, bootstrapTags, err := buildDnsGroupMembers(
		DNSBootstrapTag,
		directServers,
		DNSLocalTag,
		"",
	)
	if err != nil {
		return err
	}
	bootstrapGroup, err := getGroupDNSServerOptions(
		DNSBootstrapTag,
		bootstrapTags,
		opt.DirectDnsGroupMode,
		opt.DirectDnsErrorTTL,
		opt.DirectDnsWinTTL,
	)
	if err != nil {
		return err
	}

	remoteMembers, remoteTags, err := buildDnsGroupMembers(
		DNSRemoteTag,
		remoteServers,
		DNSBootstrapTag,
		remoteDetour,
	)
	if err != nil {
		return err
	}
	remoteGroup, err := getGroupDNSServerOptions(
		DNSRemoteTag,
		remoteTags,
		opt.RemoteDnsGroupMode,
		opt.RemoteDnsErrorTTL,
		opt.RemoteDnsWinTTL,
	)
	if err != nil {
		return err
	}

	servers := []option.DNSServerOptions{*local}
	servers = append(servers, bootstrapMembers...)
	servers = append(servers, *bootstrapGroup)
	servers = append(servers, remoteMembers...)
	servers = append(servers, *remoteGroup)
	if staticIps != nil && len(*staticIps) > 0 {
		static_dns, err := getStaticDNSServerOptions(DNSStaticTag, staticIps)
		if err != nil {
			return err
		}
		servers = append([]option.DNSServerOptions{*static_dns}, servers...)
	}

	dnsOptions := option.DNSOptions{
		RawDNSOptions: option.RawDNSOptions{
			DNSClientOptions: option.DNSClientOptions{
				// sing-box 1.14+ deprecates independent_cache; keep disabled for forward compatibility.
				IndependentCache: false,
				DisableExpire:    true,
			},
			Final:   DNSRemoteTag,
			Servers: servers,
			Rules:   []option.DNSRule{},
		},
	}
	if opt.EnableFakeDNS {
		inet4Range := badoption.Prefix(netip.MustParsePrefix("198.18.0.0/15"))
		inet6Range := badoption.Prefix(netip.MustParsePrefix("fc00::/18"))
		dnsOptions.Servers = append(dnsOptions.Servers, option.DNSServerOptions{
			Tag:  DNSFakeTag,
			Type: C.DNSTypeFakeIP,
			Options: &option.FakeIPDNSServerOptions{
				Inet4Range: &inet4Range,
				Inet6Range: &inet6Range,
			},
		})
	}
	options.DNS = &dnsOptions
	return nil
}

func resolveDnsServerList(servers []string, fallback string) []string {
	out := make([]string, 0, len(servers))
	seen := map[string]struct{}{}
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) > 0 {
		return out
	}
	return []string{fallback}
}

func buildDnsGroupMembers(
	groupTag string,
	addresses []string,
	domainResolver string,
	detour string,
) ([]option.DNSServerOptions, []string, error) {
	members := make([]option.DNSServerOptions, 0, len(addresses))
	tags := make([]string, 0, len(addresses))
	for i, addr := range addresses {
		tag := fmt.Sprintf("%s-%d", groupTag, i)
		member, err := getDNSServerOptions(tag, getDnsAddress(addr), domainResolver, detour)
		if err != nil && domainResolver != "" {
			// plain IP / udp without needing local resolver
			member, err = getDNSServerOptions(tag, getDnsAddress(addr), "", detour)
		}
		if err != nil {
			return nil, nil, err
		}
		members = append(members, *member)
		tags = append(tags, tag)
	}
	return members, tags, nil
}

func getGroupDNSServerOptions(
	tag string,
	memberTags []string,
	mode string,
	errorTTL string,
	winTTL string,
) (*option.DNSServerOptions, error) {
	if len(memberTags) == 0 {
		return nil, E.New("dns group ", tag, ": servers is required")
	}
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = "stable"
	}
	opts := &option.GroupDNSServerOptions{
		Servers:  memberTags,
		Mode:     mode,
		ErrorTTL: parseDnsGroupDuration(errorTTL, 2*time.Minute),
	}
	if mode == "fastest" {
		opts.WinTTL = parseDnsGroupDuration(winTTL, 5*time.Minute)
	}
	return &option.DNSServerOptions{
		Tag:     tag,
		Type:    C.DNSTypeGroup,
		Options: opts,
	}, nil
}

func parseDnsGroupDuration(raw string, fallback time.Duration) badoption.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return badoption.Duration(fallback)
	}
	if minutes, err := strconv.Atoi(raw); err == nil {
		if minutes <= 0 {
			return badoption.Duration(fallback)
		}
		return badoption.Duration(time.Duration(minutes) * time.Minute)
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return badoption.Duration(fallback)
	}
	return badoption.Duration(d)
}

func getAllOutboundsOptions(options *option.Options) []any {
	outbounds := []any{}
	for _, o := range options.Outbounds {
		outbounds = append(outbounds, o.Options)
	}
	for _, o := range options.Endpoints {
		outbounds = append(outbounds, o.Options)
	}
	return outbounds
}
func addForceDirect(options *option.Options, hopt *ClientOptions) ([]option.DefaultDNSRule, error) {
	dnsMap := make(map[string]string)
	// outbounds := getAllOutboundsOptions(options)

	// for _, outbound := range outbounds {
	// 	// fmt.Println("out", outbound)
	// 	if server, ok := outbound.(option.ServerOptionsWrapper); ok {
	// 		serverDomain := server.TakeServerOptions().Server
	// 		detour := OutboundDirectTag
	// 		if dialer, ok := outbound.(option.DialerOptionsWrapper); ok {
	// 			if server_detour := dialer.TakeDialerOptions().Detour; server_detour != "" {
	// 				detour = server_detour
	// 			}
	// 		}
	// 		fmt.Println("serverDomain", serverDomain, "detour", detour)

	// 		if host, err := getHostnameIfNotIP(serverDomain); err == nil && host != "" {
	// 			fmt.Println("serverDomain", serverDomain, "host", host, "detour", detour)
	// 			if _, ok := dnsMap[host]; !ok || detour == OutboundDirectTag {
	// 				dnsMap[host] = detour
	// 			}
	// 		}
	// 	}
	// }

	// // dnsMap[]
	forceDirectRules := []option.DefaultDNSRule{}
	// if len(dnsMap) > 0 {
	// 	unique_dns_detours := make(map[string]bool)
	// 	for _, detour := range dnsMap {
	// 		unique_dns_detours[detour] = true
	// 	}

	// 	for detour := range unique_dns_detours {
	// 		domains := []string{}
	// 		for domain, d := range dnsMap {
	// 			if d == detour {
	// 				domains = append(domains, domain)
	// 			}
	// 		}
	// 		if len(domains) == 0 {
	// 			continue
	// 		}
	// 		dns_detour := DNSMultiDirectTag
	// 		if detour != OutboundDirectTag {
	// 			dns_detour = "dns-" + detour
	// 			remote_dns, err := getDNSServerOptions(dns_detour, hopt.RemoteDnsAddress, DNSDirectTag, detour)
	// 			if err != nil {
	// 				return nil, err
	// 			}
	// 			options.DNS.Servers = append(options.DNS.Servers, *remote_dns)

	// 		}

	// 		forceDirectRules = append(forceDirectRules,
	// 			option.DefaultDNSRule{
	// 				RawDefaultDNSRule: option.RawDefaultDNSRule{
	// 					Domain: domains,
	// 				},
	// 				DNSRuleAction: option.DNSRuleAction{
	// 					Action: C.RuleActionTypeRoute,
	// 					RouteOptions: option.DNSRouteActionOptions{
	// 						Server:         dns_detour,
	// 						BypassIfFailed: false,
	// 					},
	// 				},
	// 			},
	// 		)
	// 	}
	// }

	forceDirectRules = append(forceDirectRules,
		option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				Domain: []string{"api.cloudflareclient.com"},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action:       C.RuleActionTypeRoute,
				RouteOptions: dnsRouteWithOptionalStrategy(DNSRemoteTag, hopt.DirectDnsDomainStrategy, hopt.EnableFakeDNS, &DEFAULT_DNS_TTL, false),
			},
		},
	)

	dnsMap["api.cloudflareclient.com"] = ""
	for _, url := range connectionTestURLsForDNS(hopt) { //To avoid dns bug when using urltest
		if host, err := getHostnameIfNotIP(url); err == nil {
			dnsMap[host] = ""
		}
	}
	// for _, d := range ipinfo.GetAllIPCheckerDomainsDomains() {
	// 	dnsMap[d] = ""
	// }
	domains := []string{}
	for domain := range dnsMap {
		domains = append(domains, domain)
	}
	if len(domains) > 0 {
		forceDirectRules = append(forceDirectRules,
			option.DefaultDNSRule{
				RawDefaultDNSRule: option.RawDefaultDNSRule{
					Domain: domains,
				},
				DNSRuleAction: option.DNSRuleAction{
					Action:       C.RuleActionTypeRoute,
					RouteOptions: dnsRouteWithOptionalStrategy(DNSMultiDirectTag, hopt.DirectDnsDomainStrategy, hopt.EnableFakeDNS, &DEFAULT_DNS_TTL, false),
				},
			},
		)
		// forceDirectRules = append(forceDirectRules,
		// 	option.DefaultDNSRule{
		// 		RawDefaultDNSRule: option.RawDefaultDNSRule{
		// 			Domain: domains,
		// 		},
		// 		DNSRuleAction: option.DNSRuleAction{
		// 			Action: C.RuleActionTypeRoute,
		// 			RouteOptions: option.DNSRouteActionOptions{
		// 				Server:         DNSTricksDirectTag,
		// 				Strategy:       hopt.DirectDnsDomainStrategy,
		// 				BypassIfFailed: false,
		// 			},
		// 		},
		// 	},
		// )
		// forceDirectRules = append(forceDirectRules,
		// 	option.DefaultDNSRule{
		// 		RawDefaultDNSRule: option.RawDefaultDNSRule{
		// 			Domain: domains,
		// 		},
		// 		DNSRuleAction: option.DNSRuleAction{
		// 			Action: C.RuleActionTypeRoute,
		// 			RouteOptions: option.DNSRouteActionOptions{
		// 				Server:         DNSLocalTag,
		// 				Strategy:       hopt.DirectDnsDomainStrategy,
		// 				BypassIfFailed: false,
		// 			},
		// 		},
		// 	},
		// )
	}
	return forceDirectRules, nil

}

func getDNSServerOptions(tag string, dnsurl string, domain_resolver string, detour string) (*option.DNSServerOptions, error) {
	serverURL, _ := url.Parse(dnsurl)
	var serverType string
	if serverURL != nil && serverURL.Scheme != "" {
		serverType = serverURL.Scheme
	} else {
		switch dnsurl {
		case "local", "fakeip":
			serverType = dnsurl
		default:
			serverType = C.DNSTypeUDP
		}
	}
	if res, _ := getHostnameIfNotIP(dnsurl); res == "" {
		domain_resolver = ""
	}
	remoteOptions := option.RemoteDNSServerOptions{
		RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
			DialerOptions: dialerWithResolver(detour, domain_resolver, option.DomainStrategy(C.DomainStrategyPreferIPv4)),
		},
	}
	o := option.DNSServerOptions{
		Tag: tag,
	}
	switch serverType {
	case C.DNSTypeLocal:
		o.Type = C.DNSTypeLocal
		o.Options = &option.LocalDNSServerOptions{
			RawLocalDNSServerOptions: remoteOptions.RawLocalDNSServerOptions,
			PreferGo:                 true,
		}
	case C.DNSTypeUDP:
		o.Type = C.DNSTypeUDP
		o.Options = &remoteOptions
		var serverAddr M.Socksaddr
		if serverURL == nil || serverURL.Scheme == "" {
			serverAddr = M.ParseSocksaddr(dnsurl)
		} else {
			serverAddr = M.ParseSocksaddr(serverURL.Host)
		}
		if !serverAddr.IsValid() {
			return nil, E.New("invalid server address")
		}
		remoteOptions.Server = serverAddr.AddrString()
		if serverAddr.Port != 0 && serverAddr.Port != 53 {
			remoteOptions.ServerPort = serverAddr.Port
		}
		remoteOptions.ConnectTimeout = badoption.Duration(5 * time.Second)
		remoteOptions.DisableTCPKeepAlive = true
	case C.DNSTypeTCP:
		o.Type = C.DNSTypeTCP
		o.Options = &remoteOptions
		if serverURL == nil {
			return nil, E.New("invalid server address")
		}
		serverAddr := M.ParseSocksaddr(serverURL.Host)
		if !serverAddr.IsValid() {
			return nil, E.New("invalid server address")
		}
		remoteOptions.Server = serverAddr.AddrString()
		if serverAddr.Port != 0 && serverAddr.Port != 53 {
			remoteOptions.ServerPort = serverAddr.Port
		}
	case C.DNSTypeTLS, C.DNSTypeQUIC:
		o.Type = serverType
		if serverURL == nil {
			return nil, E.New("invalid server address")
		}
		serverAddr := M.ParseSocksaddr(serverURL.Host)
		if !serverAddr.IsValid() {
			return nil, E.New("invalid server address")
		}
		remoteOptions.Server = serverAddr.AddrString()
		if serverAddr.Port != 0 && serverAddr.Port != 853 {
			remoteOptions.ServerPort = serverAddr.Port
		}
		o.Options = &option.RemoteTLSDNSServerOptions{
			RemoteDNSServerOptions: remoteOptions,
		}
	case C.DNSTypeHTTPS, C.DNSTypeHTTP3:
		o.Type = serverType
		httpsOptions := option.RemoteHTTPSDNSServerOptions{
			RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{
				RemoteDNSServerOptions: remoteOptions,
			},
		}
		o.Options = &httpsOptions
		if serverURL == nil {
			return nil, E.New("invalid server address")
		}
		serverAddr := M.ParseSocksaddr(serverURL.Host)
		if !serverAddr.IsValid() {
			return nil, E.New("invalid server address")
		}
		httpsOptions.Server = serverAddr.AddrString()
		if serverAddr.Port != 0 && serverAddr.Port != 443 {
			httpsOptions.ServerPort = serverAddr.Port
		}
		if serverURL.Path != "/dns-query" {
			httpsOptions.Path = serverURL.Path
		}
		httpsOptions.TLS = &option.OutboundTLSOptions{
			Enabled: true,
		}
		if strings.Contains(dnsurl, "#fragment=") {

			httpsOptions.TLS.Fragment = true
			httpsOptions.TLS.RecordFragment = true

			splt := strings.Split(dnsurl, "#fragment=")
			data := splt[len(splt)-1]
			if delay, err := strconv.Atoi(data); err == nil && delay >= 0 {
				httpsOptions.TLS.FragmentFallbackDelay = badoption.Duration(time.Duration(delay) * time.Millisecond)
			} else {
				// httpsOptions.TLS.FragmentFallbackDelay = badoption.Duration(30 * time.Millisecond)
			}

		}
	// case "rcode":
	// 	var rcode int
	// 	if serverURL == nil {
	// 		return nil, E.New("invalid server address")
	// 	}
	// 	switch serverURL.Host {
	// 	case "success":
	// 		rcode = dnscode.RcodeSuccess
	// 	case "format_error":
	// 		rcode = dnscode.RcodeFormatError
	// 	case "server_failure":
	// 		rcode = dnscode.RcodeServerFailure
	// 	case "name_error":
	// 		rcode = dnscode.RcodeNameError
	// 	case "not_implemented":
	// 		rcode = dnscode.RcodeNotImplemented
	// 	case "refused":
	// 		rcode = dnscode.RcodeRefused
	// 	default:
	// 		return nil, E.New("unknown rcode: ", serverURL.Host)
	// 	}
	// 	o.Type = C.DNSTypeLegacyRcode
	// 	o.Options = rcode
	case C.DNSTypeDHCP:
		o.Type = C.DNSTypeDHCP
		dhcpOptions := option.DHCPDNSServerOptions{}
		if serverURL == nil {
			return nil, E.New("invalid server address")
		}
		if serverURL.Host != "" && serverURL.Host != "auto" {
			dhcpOptions.Interface = serverURL.Host
		}
		o.Options = &dhcpOptions
	case C.DNSTypeFakeIP:
		o.Type = C.DNSTypeFakeIP
		fakeipOptions := option.FakeIPDNSServerOptions{}
		// if legacyOptions, loaded := ctx.Value((*option.LegacyDNSFakeIPOptions)(nil)).(*option.LegacyDNSFakeIPOptions); loaded {
		// 	fakeipOptions.Inet4Range = legacyOptions.Inet4Range
		// 	fakeipOptions.Inet6Range = legacyOptions.Inet6Range
		// }
		o.Options = &fakeipOptions
	default:
		return nil, E.New("unsupported DNS server scheme: ", serverType)

	}
	return &o, nil
}

func getStaticDNSServerOptions(tag string, staticIps *map[string][]string) (*option.DNSServerOptions, error) {
	domain_ips := badjson.TypedMap[string, badoption.Listable[netip.Addr]]{}
	for domain, ips := range *staticIps {
		ipsConverted := make([]netip.Addr, 0, len(ips))
		for _, ip := range ips {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, err
			}
			ipsConverted = append(ipsConverted, addr)
		}
		domain_ips.Put(domain, ipsConverted)
	}
	o := option.DNSServerOptions{
		Tag:  tag,
		Type: C.DNSTypeHosts,
		Options: &option.HostsDNSServerOptions{
			Predefined: &domain_ips,
		},
	}
	return &o, nil
}
func getMultiDnsServerOptions(tag string, servers []string, parallel bool) (*option.DNSServerOptions, error) {
	// LX-STUB: C.DNSTypeMulti / MultiDNSServerOptions are Hiddify-only.
	// Fall back to the first listed server as a plain UDP DNS server.
	_ = parallel
	server := "1.1.1.1"
	if len(servers) > 0 && servers[0] != "" {
		server = servers[0]
	}
	remoteOptions := option.RemoteDNSServerOptions{
		DNSServerAddressOptions: option.DNSServerAddressOptions{
			Server: server,
		},
	}
	o := option.DNSServerOptions{
		Tag:     tag,
		Type:    C.DNSTypeUDP,
		Options: &remoteOptions,
	}
	return &o, nil
}

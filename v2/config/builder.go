package config

import (
	context "context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	sync "sync"
	"time"

	"github.com/hiddify/hiddify-core/v2/hutils"
	mDNS "github.com/miekg/dns"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func normalizeBalancerStrategy(strategy string) string {
	switch strategy {
	case "roundRobin":
		return "round-robin"
	default:
		return strategy
	}
}

const (
	DNSRemoteTag         = "dns-remote"
	DNSRemoteTagFallback = "dns-remote-fallback" // legacy unused
	DNSLocalTag          = "dns-local"
	DNSStaticTag         = "dns-static"
	DNSBootstrapTag      = "dns-bootstrap"
	DNSDirectTag         = DNSBootstrapTag // bootstrap resolves outbound server addresses
	DNSFakeTag           = "dns-fake"
	DNSTricksDirectTag   = "dns-trick-direct" // legacy unused
	DNSMultiDirectTag    = DNSBootstrapTag
	DNSMultiRemoteTag    = DNSRemoteTag

	OutboundDirectTag = "direct §hide§"
	OutboundBypassTag = "bypass §hide§"
	// OutboundBlockTag          = "block §hide§"
	OutboundSelectTag         = "select"
	OutboundURLTestTag        = "lowest"
	OutboundRoundRobinTag     = "balance"
	OutboundDNSTag            = "dns-out §hide§"
	OutboundDirectFragmentTag = "direct-fragment §hide§"

	InboundTUNTag    = "tun-in"
	InboundMixedTag  = "mixed-in"
	InboundTProxy    = "tproxy-in"
	InboundRedirect  = "redirect-in"
	InboundDirectTag = "dns-in"
)

var (
	OutboundMainDetour     = OutboundSelectTag
	PredefinedOutboundTags = []string{OutboundDirectTag, OutboundBypassTag, OutboundSelectTag, OutboundURLTestTag, OutboundDNSTag, OutboundDirectFragmentTag}
)

// BuildConfig merges layers:
//
//	L1 plane — outbounds/endpoints + selector (setOutbounds)
//	L2 dns — subscription dns as-is, or simple/advanced client template (setDns)
//	L3 client hooks — sniff; optional hijack-dns (setRoutingOptions)
//	L4 route policy — local RoutingProfile + subscription route merge (setRoutingOptions)
func BuildConfig(ctx context.Context, hopts *HiddifyOptions, inputOpt *ReadOptions) (*option.Options, error) {

	input, err := ReadSingOptions(ctx, inputOpt)
	if err != nil {
		return nil, err
	}

	var options option.Options
	if hopts.EnableFullConfig {
		options.Inbounds = input.Inbounds
		options.DNS = input.DNS
		options.Route = input.Route
	}

	setExperimental(&options, hopts)

	setLog(&options, hopts)
	setInbound(&options, hopts)
	staticIPs := make(map[string][]string)
	if err := setOutbounds(&options, input, hopts, &staticIPs); err != nil {
		return nil, err
	}

	useSubDNS := input.DNS != nil && len(input.DNS.Servers) > 0 && !hopts.IgnoreSubscriptionDNS
	if useSubDNS {
		options.DNS = input.DNS
	} else if err := setDns(&options, hopts, &staticIPs); err != nil {
		return nil, err
	}

	if err := setRoutingOptions(&options, input, hopts, useSubDNS); err != nil {
		return nil, err
	}

	return &options, nil
}

func setNTP(options *option.Options) {
	options.NTP = &option.NTPOptions{
		Enabled:       true,
		ServerOptions: option.ServerOptions{ServerPort: 123, Server: "time.apple.com"},
		Interval:      badoption.Duration(12 * time.Hour),
		DialerOptions: option.DialerOptions{
			Detour: OutboundDirectTag,
		},
	}
}

func getHostnameIfNotIP(inp string) (string, error) {
	if inp == "" {
		return "", fmt.Errorf("empty hostname: %s", inp)
	}
	if net.ParseIP(strings.Trim(inp, "[]")) == nil {
		inp2 := inp
		if !strings.Contains(inp, "://") {
			inp2 = "http://" + inp
		}
		u, err := url.Parse(inp2)
		if err != nil {
			return inp, nil
		}
		if net.ParseIP(strings.Trim(u.Host, "[]")) == nil {
			return u.Host, nil
		}
	}
	return "", fmt.Errorf("not a hostname: %s", inp)
}

func isOutboundDisabled(tag string, disabled []string) bool {
	return contains(disabled, tag)
}

func setOutbounds(options *option.Options, input *option.Options, opt *HiddifyOptions, staticIPs *map[string][]string) error {
	var outbounds []option.Outbound
	var endpoints []option.Endpoint
	var tags []string
	OutboundMainDetour = OutboundSelectTag
	detours := resolvedChainDetours(opt.Chain)
	knownExits := chainKnownExitSet(input)
	for _, out := range input.Outbounds {

		if contains(PredefinedOutboundTags, out.Tag) {
			continue
		}
		outbound, err := patchOutbound(out, *opt, staticIPs)
		if err != nil {
			return err
		}
		out = *outbound
		if exit := chainExitFor(out.Tag, detours, knownExits); exit != "" {
			out = applyDetourToOutbound(out, exit)
		}

		switch out.Type {
		case C.TypeBlock, C.TypeDNS:
			continue
		case C.TypeSelector, C.TypeURLTest, C.TypeBalancer:
			continue
		case "custom": // LX-STUB: C.TypeCustom absent in sing-box-lx
			continue
		default:

			if contains([]string{"direct", "bypass", "block"}, out.Tag) {
				continue
			}
			if !strings.Contains(out.Tag, "§hide§") && !isOutboundDisabled(out.Tag, opt.DisabledOutboundTags) {
				tags = append(tags, out.Tag)
			}
			outbounds = append(outbounds, out)
		}
	}

	for _, end := range input.Endpoints {
		if contains(PredefinedOutboundTags, end.Tag) {
			continue
		}

		out, err := patchEndpoint(&end, *opt, staticIPs)
		if err != nil {
			return err
		}
		if exit := chainExitFor(out.Tag, detours, knownExits); exit != "" {
			applyDetourToEndpoint(out, exit)
		}

		if !strings.Contains(out.Tag, "§hide§") && !isOutboundDisabled(out.Tag, opt.DisabledOutboundTags) {
			tags = append(tags, out.Tag)
		}

		endpoints = append(endpoints, *out)
	}

	// WARP nodes live in a dedicated local profile (Flutter WarpAutoProfileSync).
	// Do not mix them into other profiles — multi-select merge covers composition.
	if len(opt.ConnectionTestUrls) == 0 {
		opt.ConnectionTestUrls = []string{opt.ConnectionTestUrl}
	}
	// urlTest := option.Outbound{
	// 	Type: C.TypeURLTest,
	// 	Tag:  OutboundURLTestTag,
	// 	Options: &option.URLTestOutboundOptions{
	// 		Outbounds: tags,
	// 		URL:       opt.ConnectionTestUrl,
	// 		URLs:      opt.ConnectionTestUrls,
	// 		Interval:  badoption.Duration(opt.URLTestInterval.Duration()),
	// 		// IdleTimeout: badoption.Duration(opt.URLTestIdleTimeout.Duration()),
	// 		Tolerance:                 1,
	// 		IdleTimeout:               badoption.Duration(opt.URLTestInterval.Duration().Nanoseconds() * 3),
	// 		InterruptExistConnections: true,
	// 	},
	// }
	// Preferred node from subscription marker (exact tag, not the marker alone).
	preferred := ""
	for _, tag := range tags {
		if strings.Contains(tag, "§default§") {
			preferred = tag
			break
		}
	}

	// Two balancers as selectable modes under `select` (not route.final):
	//   lowest  — auto best latency (urltest replacement)
	//   balance — load strategy from settings (round-robin / …)
	// lx balancer.default: pin while Alive; Dead → strategy among the rest.
	lowestOpts := &option.BalancerOutboundOptions{
		Outbounds:                 tags,
		Default:                   preferred,
		Strategy:                  "lowest-delay",
		DelayAcceptableRatio:      2,
		Tolerance:                 1,
		InterruptExistConnections: true,
	}
	balanceOpts := &option.BalancerOutboundOptions{
		Outbounds:                 tags,
		Default:                   preferred,
		Strategy:                  normalizeBalancerStrategy(opt.BalancerStrategy),
		DelayAcceptableRatio:      2,
		Tolerance:                 1,
		InterruptExistConnections: true,
	}
	urlTest := option.Outbound{
		Type:    C.TypeBalancer,
		Tag:     OutboundURLTestTag,
		Options: lowestOpts,
	}
	balancer := option.Outbound{
		Type:    C.TypeBalancer,
		Tag:     OutboundRoundRobinTag,
		Options: balanceOpts,
	}

	// Traffic path: route.final → select → (balance|lowest|node) → nodes.
	// Keep final on select so UI/SelectOutbound can switch modes and nodes.
	if len(tags) == 0 {
		// Direct-only / empty leaf pool: select → direct (no empty balancers).
		selector := option.Outbound{
			Type: C.TypeSelector,
			Tag:  OutboundSelectTag,
			Options: &option.SelectorOutboundOptions{
				Outbounds:                 []string{OutboundDirectTag},
				Default:                   OutboundDirectTag,
				InterruptExistConnections: true,
			},
		}
		options.Endpoints = endpoints
		options.Outbounds = append(
			[]option.Outbound{selector},
			append(outbounds,
				option.Outbound{
					Tag:     OutboundDirectTag,
					Type:    C.TypeDirect,
					Options: &option.DirectOutboundOptions{},
				},
				option.Outbound{
					Tag:  OutboundDirectFragmentTag,
					Type: C.TypeDirect,
					Options: &option.DirectOutboundOptions{
						DialerOptions: option.DialerOptions{
							AbstractDialerOptions: option.AbstractDialerOptions{
								TCPFastOpen: false,
							},
						},
					},
				},
			)...,
		)
		return nil
	}

	defaultSelect := ""
	if len(tags) > 0 {
		defaultSelect = tags[0]
	}
	selectorTags := append([]string{}, tags...)
	if len(tags) > 1 {
		selectorTags = append([]string{urlTest.Tag, balancer.Tag}, selectorTags...)
		defaultSelect = balancer.Tag // auto load-balance until user picks otherwise
	}
	if preferred != "" {
		defaultSelect = preferred // explicit §default§ wins over auto balance
	}

	selector := option.Outbound{
		Type: C.TypeSelector,
		Tag:  OutboundSelectTag,
		Options: &option.SelectorOutboundOptions{
			Outbounds:                 selectorTags,
			Default:                   defaultSelect,
			InterruptExistConnections: true,
		},
	}
	outbounds = append([]option.Outbound{selector, urlTest, balancer}, outbounds...)
	options.Endpoints = endpoints
	options.Outbounds = append(
		outbounds,
		[]option.Outbound{
			{
				Tag:     OutboundDirectTag,
				Type:    C.TypeDirect,
				Options: &option.DirectOutboundOptions{},
			},
			{
				Tag:  OutboundDirectFragmentTag,
				Type: C.TypeDirect,
				Options: &option.DirectOutboundOptions{
					DialerOptions: option.DialerOptions{
						AbstractDialerOptions: option.AbstractDialerOptions{
							TCPFastOpen: false,
						},
					},
				},
			},
		}...,
	)

	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func setExperimental(options *option.Options, hopt *HiddifyOptions) {
	if len(hopt.ConnectionTestUrls) == 0 {
		hopt.ConnectionTestUrls = []string{hopt.ConnectionTestUrl}
	}
	exp := &option.ExperimentalOptions{
		CacheFile: &option.CacheFileOptions{
			Enabled:     true,
			Path:        "data/clash.db",
			StoreFakeIP: hopt.EnableFakeDNS,
		},
		// LX-STUB: MonitoringOptions (URL-test monitor) absent in sing-box-lx ExperimentalOptions
	}
	if hopt.EnableClashApi {
		// Secret must come from the client (persisted web-secret). Do not randomize
		// here — a generated value would desync Dart Bearer auth for Connections.
		exp.ClashAPI = &option.ClashAPIOptions{
			ExternalController: fmt.Sprintf("%s:%d", "127.0.0.1", hopt.ClashApiPort),
			Secret:             hopt.ClashApiSecret,
		}
	}
	options.Experimental = exp
}

func setLog(options *option.Options, opt *HiddifyOptions) {
	logOutput := opt.LogFile
	logDisabled := strings.TrimSpace(logOutput) == ""
	options.Log = &option.LogOptions{
		Level:        opt.LogLevel,
		Output:       logOutput,
		Disabled:     logDisabled,
		Timestamp:    false,
		DisableColor: true,
	}
}
func isIPv6Supported() bool {
	if C.IsIos || C.IsDarwin {
		return true
	}
	_, err := net.ResolveIPAddr("ip6", "::1")
	return err == nil
}

func tunAddressesForIPv6Mode(mode option.DomainStrategy, ipv6Supported bool) []netip.Prefix {
	v4Prefix := netip.MustParsePrefix("172.19.0.1/28")
	v6Prefix := netip.MustParsePrefix("fdfe:dcba:9876::1/126")

	switch mode {
	case option.DomainStrategy(C.DomainStrategyIPv4Only):
		return []netip.Prefix{v4Prefix}
	case option.DomainStrategy(C.DomainStrategyIPv6Only):
		if ipv6Supported {
			return []netip.Prefix{v6Prefix}
		}
		return []netip.Prefix{v4Prefix}
	default:
		addresses := []netip.Prefix{v4Prefix}
		if ipv6Supported {
			addresses = append(addresses, v6Prefix)
		}
		return addresses
	}
}

func defaultNetworkStrategyForIPv6Mode(mode option.DomainStrategy) *option.NetworkStrategy {
	switch mode {
	case option.DomainStrategy(C.DomainStrategyPreferIPv4),
		option.DomainStrategy(C.DomainStrategyIPv4Only),
		option.DomainStrategy(C.DomainStrategyPreferIPv6),
		option.DomainStrategy(C.DomainStrategyIPv6Only):
		strategy := option.NetworkStrategy(C.NetworkStrategyFallback)
		return &strategy
	default:
		return nil
	}
}

func setInbound(options *option.Options, hopt *HiddifyOptions) {
	ipv6Enable := isIPv6Supported()
	if hopt.EnableTun {

		opts := option.TunInboundOptions{
			Stack:         hopt.TUNStack,
			MTU:           hopt.MTU,
			AutoRoute:     true,
			StrictRoute:   hopt.StrictRoute,
			InterfaceName: hutils.TunInterfaceName,
			// Align with UI DNS hijack: lx default dns_mode is hijack; when UI hijack is off
			// keep TUN from silently hijacking :53 (route rule also omitted).
			DNSMode: map[bool]string{true: "hijack", false: "native"}[hopt.EnableDnsHijack],
			Address: tunAddressesForIPv6Mode(hopt.IPv6Mode, ipv6Enable),
		}
		tunInbound := option.Inbound{
			Type: C.TypeTun,
			Tag:  InboundTUNTag,

			Options: &opts,
		}

		options.Inbounds = append(options.Inbounds, tunInbound)

	}

	binds := []string{}

	if hopt.AllowConnectionFromLAN {
		if ipv6Enable {
			binds = append(binds, "::")
		} else {
			binds = append(binds, "0.0.0.0")
		}
	} else {
		if ipv6Enable {
			binds = append(binds, "::1")
		}
		binds = append(binds, "127.0.0.1")
	}

	for _, bind := range binds {
		addr := badoption.Addr(netip.MustParseAddr(bind))

		// Always expose mixed-port when configured: required for system-proxy, app IP
		// probes, and TUN-side localhost checks. Without it, configs had zero inbounds.
		if hopt.MixedPort > 0 {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeMixed,
					Tag:  InboundMixedTag + bind,
					Options: &option.HTTPMixedInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.MixedPort,
						},
						SetSystemProxy: hopt.SetSystemProxy,
					},
				},
			)
		}
		if C.IsLinux && !C.IsAndroid && hopt.EnableTProxyPort && hopt.TProxyPort > 0 && hutils.IsAdmin() {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeTProxy,
					Tag:  InboundTProxy + bind,
					Options: &option.TProxyInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.TProxyPort,
						},
					},
				},
			)
		}
		if (C.IsLinux || C.IsDarwin) && !C.IsAndroid && hopt.EnableRedirectPort && hopt.RedirectPort > 0 {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeRedirect,
					Tag:  InboundRedirect + bind,
					Options: &option.RedirectInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.RedirectPort,
						},
					},
				},
			)
		}
		if hopt.EnableDirectPort && hopt.DirectPort > 0 {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeDirect,
					Tag:  InboundDirectTag + bind,
					Options: &option.DirectInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.DirectPort,
						},
					},
				},
			)
		}
	}
}

func setRoutingOptions(options *option.Options, input *option.Options, hopt *HiddifyOptions, useSubDNS bool) error {
	dnsRules := []option.DefaultDNSRule{}
	routeRules := []option.Rule{}
	rulesets := []option.RuleSet{}

	if !useSubDNS {
		forceDirectRules, err := addForceDirect(options, hopt)
		if err != nil {
			return err
		}
		dnsRules = append(dnsRules, forceDirectRules...)
	}

	// L3: sniff always; hijack-dns only when UI enables it (default off).
	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeSniff,
			},
		},
	})
	if hopt.EnableDnsHijack {
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					Protocol: []string{C.ProtocolDNS},
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeHijackDNS,
				},
			},
		})
	}

	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,

		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				IPCIDR: []string{
					"10.10.34.0/24",
					"2001:4188:2:600:10:10:34:0/120",
				},
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: OutboundMainDetour,
				},
			},
		},
	})

	if hopt.BypassLAN {
		// Before profile: private RFC1918/ULA/link-local/loopback (sing IPIsPrivate).
		routeRules = append(
			routeRules,
			option.Rule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{
						IPIsPrivate: true,
					},
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{
							Outbound: OutboundDirectTag,
						},
					},
				},
			},
			// CGNAT (RFC 6598) — not covered by Go netip.IsPrivate / IPIsPrivate.
			option.Rule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{
						IPCIDR: []string{"100.64.0.0/10"},
					},
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{
							Outbound: OutboundDirectTag,
						},
					},
				},
			},
		)
	}

	forceDirectRoute := make([]string, 0)
	if options.NTP != nil && options.NTP.Enabled {
		forceDirectRoute = append(forceDirectRoute, options.NTP.Server)
	}

	if len(forceDirectRoute) > 0 {

		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				Domain: forceDirectRoute,
			},
			DNSRuleAction: option.DNSRuleAction{
				Action:       C.RuleActionTypeRoute,
				RouteOptions: dnsRouteAction(DNSMultiDirectTag, hopt.DirectDnsDomainStrategy, &DEFAULT_DNS_TTL, false),
			},
		})
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					Domain: forceDirectRoute,
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{
						Outbound: OutboundDirectTag,
					},
				},
			},
		})
	}

	// L4: client-owned ads block (before profile buckets and subscription overlay).
	if hopt.BlockAds && hopt.AdsRuleSetPath != "" {
		appendAdsBlockRules(&rulesets, &routeRules, hopt.AdsRuleSetPath)
	}

	// L4: client-owned route — local profile stack first, then optional subscription overlay.
	var localRS []option.RuleSet
	var localRules []option.Rule
	profiles := hopt.RoutingProfiles
	if len(profiles) == 0 && hopt.RoutingProfile != nil {
		profiles = []*RoutingProfile{hopt.RoutingProfile}
	}
	for _, rp := range profiles {
		if rp == nil || !rp.Enabled {
			continue
		}
		rs, rules := CompileRoutingProfile(rp, hopt.GeoIPRuleSetURL, hopt.GeoSiteRuleSetURL)
		localRS = append(localRS, rs...)
		localRules = append(localRules, rules...)
	}
	for _, rs := range localRS {
		rulesets = append(rulesets, rs)
	}
	routeRules = append(routeRules, localRules...)

	// After profile: reject remaining QUIC so LAN / "No VPN" (direct) keep QUIC.
	if hopt.RouteOptions.BlockQuic {
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					Protocol: []string{C.ProtocolQUIC},
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

	// Subscription route is raw merge at connect time only (never auto-imported into local profile).
	// Local rules are always evaluated first so the client wins conflicts.
	if input != nil && input.Route != nil && !hopt.IgnoreSubscriptionRoute {
		MergeSubscriptionRoute(input.Route, &rulesets, &routeRules)
	}

	sanitized, err := sanitizeRuleSetsLocalOnly(rulesets)
	if err != nil {
		return err
	}
	rulesets = sanitized

	final := OutboundMainDetour
	globalProxy := true
	if hopt.RoutingGlobalProxy != nil {
		globalProxy = *hopt.RoutingGlobalProxy
	} else if len(profiles) == 1 && profiles[0] != nil {
		globalProxy = profiles[0].GlobalProxy
	} else if hopt.RoutingProfile != nil {
		globalProxy = hopt.RoutingProfile.GlobalProxy
	}
	anyEnabled := false
	for _, rp := range profiles {
		if rp != nil && rp.Enabled {
			anyEnabled = true
			break
		}
	}
	if anyEnabled && !globalProxy {
		final = OutboundDirectTag
	}

	strategy := defaultNetworkStrategyForIPv6Mode(hopt.IPv6Mode)
	// sing-box requires auto_detect_interface whenever default_network_strategy is set.
	autoDetect := (!C.IsAndroid && !C.IsIos) && (hopt.EnableTun || hopt.EnableTunService || strategy != nil)

	findProcess := false
	for _, rp := range profiles {
		if ProfileNeedsFindProcess(rp) {
			findProcess = true
			break
		}
	}

	options.Route = &option.RouteOptions{
		Rules:                  routeRules,
		Final:                  final,
		AutoDetectInterface:    autoDetect,
		DefaultNetworkStrategy: strategy,
		RuleSet:                rulesets,
		FindProcess:            findProcess,
	}
	if useSubDNS {
		if options.DNS != nil {
			server := options.DNS.Final
			if server == "" && len(options.DNS.Servers) > 0 {
				server = options.DNS.Servers[0].Tag
			}
			if server != "" {
				options.Route.DefaultDomainResolver = &option.DomainResolveOptions{
					Server: server,
				}
			}
		}
	} else {
		options.Route.DefaultDomainResolver = &option.DomainResolveOptions{
			Server:   DNSBootstrapTag,
			Strategy: hopt.DirectDnsDomainStrategy,
		}
		if hopt.EnableFakeDNS {
			dnsRules = append(
				dnsRules,
				option.DefaultDNSRule{
					RawDefaultDNSRule: option.RawDefaultDNSRule{
						QueryType: badoption.Listable[option.DNSQueryType]{
							option.DNSQueryType(mDNS.StringToType["A"]),
							option.DNSQueryType(mDNS.StringToType["AAAA"]),
						},
					},
					DNSRuleAction: option.DNSRuleAction{
						Action:       C.RuleActionTypeRoute,
						RouteOptions: dnsRouteAction(DNSFakeTag, hopt.RemoteDnsDomainStrategy, &DEFAULT_DNS_TTL, true),
					},
				})
		}
		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{},
			DNSRuleAction: option.DNSRuleAction{
				Action:       C.RuleActionTypeRoute,
				RouteOptions: dnsRouteAction(DNSRemoteTag, hopt.RemoteDnsDomainStrategy, &DEFAULT_DNS_TTL, false),
			},
		})
	}

	if !useSubDNS && options.DNS != nil {
		for _, dnsRule := range dnsRules {
			if dnsRule.IsValid() {
				options.DNS.Rules = append(
					options.DNS.Rules,
					option.DNSRule{
						Type:           C.RuleTypeDefault,
						DefaultOptions: dnsRule,
					},
				)
			}
		}
	}

	return nil
}


var (
	ipMaps      = map[string][]string{}
	ipMapsMutex sync.Mutex
)

func getIPs(domains ...string) []string {
	var wg sync.WaitGroup
	resChan := make(chan string, len(domains)*10) // Collect both IPv4 and IPv6
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	for _, d := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
			if err != nil {
				return
			}
			for _, ip := range ips {
				ipStr := ip.String()
				if !isBlockedIP(ipStr) {
					resChan <- ipStr
				}
			}
		}(d)
	}

	go func() {
		wg.Wait()
		close(resChan)
	}()

	var res []string
	for ip := range resChan {
		res = append(res, ip)
	}
	if len(res) == 0 && ipMaps[domains[0]] != nil {
		return ipMaps[domains[0]]
	}
	ipMapsMutex.Lock()
	ipMaps[domains[0]] = res
	ipMapsMutex.Unlock()

	return res
}

func isBlockedDomain(domain string) bool {
	if strings.HasPrefix("full:", domain) {
		return false
	}
	if strings.Contains(domain, "instagram") || strings.Contains(domain, "facebook") || strings.Contains(domain, "telegram") || strings.Contains(domain, "t.me") {
		return true
	}
	ips := getIPs(domain)
	if len(ips) == 0 {
		// fmt.Println(err)
		return true
	}

	// // Print the IP addresses associated with the domain
	// fmt.Printf("IP addresses for %s:\n", domain)
	// for _, ip := range ips {
	// 	if isBlockedIP(ip) {
	// 		return true
	// 	}
	// }
	return false
}

func isBlockedIP(ip string) bool {
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "2001:4188:2:600:10") {
		return true
	}
	return false
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

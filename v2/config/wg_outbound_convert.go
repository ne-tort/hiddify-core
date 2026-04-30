package config

import (
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// convertWireGuardOutboundsToEndpoints turns legacy sing-box WireGuard *outbounds* into
// WireGuard *endpoints* (sing-box ≥1.10). Removes converted tags from selector/urltest/balancer lists.
// Idempotent: second pass leaves config unchanged.
func convertWireGuardOutboundsToEndpoints(options *option.Options) {
	if options == nil || len(options.Outbounds) == 0 {
		return
	}
	removed := make(map[string]struct{})
	out := make([]option.Outbound, 0, len(options.Outbounds))
	for _, ob := range options.Outbounds {
		if ob.Type != C.TypeWireGuard {
			out = append(out, ob)
			continue
		}
		leg := parseLegacyWireGuardOutboundOptions(ob)
		if leg == nil {
			out = append(out, ob)
			continue
		}
		ep := legacyWireGuardOutboundToEndpoint(ob.Tag, leg)
		options.Endpoints = upsertEndpointByTag(options.Endpoints, ep)
		removed[ob.Tag] = struct{}{}
	}
	options.Outbounds = stripOutboundTagsFromGroupOutbounds(out, removed)
}

func parseLegacyWireGuardOutboundOptions(ob option.Outbound) *option.LegacyWireGuardOutboundOptions {
	if ob.Options == nil {
		return nil
	}
	if opts, ok := ob.Options.(*option.LegacyWireGuardOutboundOptions); ok {
		return opts
	}
	if opts, ok := ob.Options.(option.LegacyWireGuardOutboundOptions); ok {
		cp := opts
		return &cp
	}
	return nil
}

func normalizeWireGuardPSK(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "<nil>") {
		return ""
	}
	return s
}

func legacyWireGuardOutboundToEndpoint(tag string, leg *option.LegacyWireGuardOutboundOptions) option.Endpoint {
	opts := &option.WireGuardEndpointOptions{
		System:                     leg.SystemInterface,
		MTU:                        leg.MTU,
		Address:                    leg.LocalAddress,
		PrivateKey:                 leg.PrivateKey,
		Noise:                      leg.Noise,
		Workers:                    leg.Workers,
		PreallocatedBuffersPerPool: leg.PreallocatedBuffersPerPool,
		DisablePauses:              leg.DisablePauses,
	}
	opts.DialerOptions = leg.DialerOptions

	peers := make([]option.WireGuardPeer, 0, len(leg.Peers)+1)
	for _, p := range leg.Peers {
		peers = append(peers, option.WireGuardPeer{
			Address:      p.Server,
			Port:         p.ServerPort,
			PublicKey:    p.PublicKey,
			PreSharedKey: normalizeWireGuardPSK(p.PreSharedKey),
			AllowedIPs:   p.AllowedIPs,
			Reserved:     p.Reserved,
		})
	}
	if len(peers) == 0 && (leg.Server != "" || leg.PeerPublicKey != "") {
		peers = append(peers, option.WireGuardPeer{
			Address:      leg.Server,
			Port:         leg.ServerPort,
			PublicKey:    leg.PeerPublicKey,
			PreSharedKey: normalizeWireGuardPSK(leg.PreSharedKey),
			Reserved:     leg.Reserved,
		})
	}
	opts.Peers = peers

	return option.Endpoint{
		Type:    C.TypeWireGuard,
		Tag:     tag,
		Options: opts,
	}
}

func upsertEndpointByTag(eps []option.Endpoint, ep option.Endpoint) []option.Endpoint {
	for i := range eps {
		if eps[i].Tag == ep.Tag {
			eps[i] = ep
			return eps
		}
	}
	return append(eps, ep)
}

func filterRemovedOutboundTags(tags []string, remove map[string]struct{}) []string {
	if len(tags) == 0 || len(remove) == 0 {
		return tags
	}
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		if _, drop := remove[t]; drop {
			continue
		}
		out = append(out, t)
	}
	return out
}

func stripOutboundTagsFromGroupOutbounds(outbounds []option.Outbound, remove map[string]struct{}) []option.Outbound {
	if len(remove) == 0 {
		return outbounds
	}
	for i := range outbounds {
		ob := &outbounds[i]
		switch ob.Type {
		case C.TypeSelector:
			if opts, ok := ob.Options.(*option.SelectorOutboundOptions); ok {
				opts.Outbounds = filterRemovedOutboundTags(opts.Outbounds, remove)
				if opts.Default != "" {
					if _, gone := remove[opts.Default]; gone {
						if len(opts.Outbounds) > 0 {
							opts.Default = opts.Outbounds[0]
						} else {
							opts.Default = ""
						}
					}
				}
			}
		case C.TypeURLTest:
			if opts, ok := ob.Options.(*option.URLTestOutboundOptions); ok {
				opts.Outbounds = filterRemovedOutboundTags(opts.Outbounds, remove)
			}
		case C.TypeBalancer:
			if opts, ok := ob.Options.(*option.BalancerOutboundOptions); ok {
				opts.Outbounds = filterRemovedOutboundTags(opts.Outbounds, remove)
			}
		}
	}
	return outbounds
}

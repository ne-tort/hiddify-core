package config

import (
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func isWarpManagedTag(tag string) bool {
	return tag == WarpWGTag || tag == WarpMasqueTag
}

func isNonLeafOutboundType(typ string) bool {
	switch typ {
	case C.TypeSelector, C.TypeURLTest, C.TypeBalancer, C.TypeBlock, C.TypeDNS, C.TypeDirect, "custom":
		return true
	default:
		return false
	}
}

func isSkippedDetourTag(tag string) bool {
	if tag == "" || strings.Contains(tag, "§hide§") {
		return true
	}
	return contains([]string{"direct", "bypass", "block"}, tag)
}

func chainMemberSet(members []string) map[string]struct{} {
	set := make(map[string]struct{}, len(members))
	for _, m := range members {
		if m != "" {
			set[m] = struct{}{}
		}
	}
	return set
}

func shouldApplyChainDetour(tag, target string, members map[string]struct{}) bool {
	if target == "" || tag == target || isSkippedDetourTag(tag) || isWarpManagedTag(tag) {
		return false
	}
	_, ok := members[tag]
	return ok
}

func applyDetourToOutbound(base option.Outbound, detour string) option.Outbound {
	if detour == "" || isSkippedDetourTag(base.Tag) || isWarpManagedTag(base.Tag) || isNonLeafOutboundType(base.Type) {
		return base
	}
	if opts, ok := base.Options.(option.DialerOptionsWrapper); ok {
		dialer := opts.TakeDialerOptions()
		dialer.Detour = detour
		opts.ReplaceDialerOptions(dialer)
	}
	return base
}

func applyDetourToEndpoint(base *option.Endpoint, detour string) {
	if base == nil || detour == "" || isSkippedDetourTag(base.Tag) || isWarpManagedTag(base.Tag) {
		return
	}
	if opts, ok := base.Options.(option.DialerOptionsWrapper); ok {
		dialer := opts.TakeDialerOptions()
		dialer.Detour = detour
		opts.ReplaceDialerOptions(dialer)
	}
}

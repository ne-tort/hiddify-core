package l3routerendpoint

import (
	"fmt"
	"net/netip"
	"strings"

	rt "github.com/sagernet/sing-box/common/l3router"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func ParseRouteOptions(ro option.L3RouterPeerOptions) (rt.Route, error) {
	var r rt.Route
	r.PeerID = rt.RouteID(ro.PeerID)
	r.User = ro.User
	var err error
	r.FilterSourceIPs, err = ParsePrefixes(ro.FilterSourceIPs)
	if err != nil {
		return rt.Route{}, fmt.Errorf("filter_source_ips: %w", err)
	}
	r.FilterDestinationIPs, err = ParsePrefixes(ro.FilterDestinationIPs)
	if err != nil {
		return rt.Route{}, fmt.Errorf("filter_destination_ips: %w", err)
	}
	r.AllowedIPs, err = ParsePrefixes(ro.AllowedIPs)
	if err != nil {
		return rt.Route{}, fmt.Errorf("allowed_ips: %w", err)
	}
	return r, nil
}

func ParsePrefixes(items []string) ([]netip.Prefix, error) {
	if len(items) == 0 {
		return nil, nil
	}
	result := make([]netip.Prefix, 0, len(items))
	seen := make(map[netip.Prefix]struct{}, len(items))
	for index, item := range items {
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("item[%d]=%q: %w", index, item, err)
		}
		prefix = prefix.Masked()
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix)
	}
	return result, nil
}

func ValidateRoute(r rt.Route) error {
	if r.PeerID == 0 {
		return E.New("peer_id must be non-zero")
	}
	if strings.TrimSpace(r.User) == "" {
		return E.New("user must be non-empty")
	}
	if len(r.AllowedIPs) == 0 {
		return E.New("allowed_ips must not be empty")
	}
	return nil
}

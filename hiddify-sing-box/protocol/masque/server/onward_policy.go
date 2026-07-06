package server

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	connectudp "github.com/sagernet/sing-box/transport/masque/connectudp"
	E "github.com/sagernet/sing/common/exceptions"
)

// OrderResolvedTCPAddrs returns public addresses with IPv4 before IPv6 for onward serial dial.
func OrderResolvedTCPAddrs(resolved []netip.Addr) []netip.Addr {
	var v4, v6 []netip.Addr
	for _, rip := range resolved {
		if rip.Is4() || rip.Is4In6() {
			v4 = append(v4, rip.Unmap())
			continue
		}
		if rip.Is6() {
			v6 = append(v6, rip)
		}
	}
	out := make([]netip.Addr, 0, len(v4)+len(v6))
	out = append(out, v4...)
	out = append(out, v6...)
	return out
}

func filterPublicTCPAddrs(resolved []netip.Addr) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(resolved))
	for _, rip := range resolved {
		if rip.IsLoopback() || rip.IsPrivate() || rip.IsMulticast() || rip.IsLinkLocalUnicast() || rip.IsLinkLocalMulticast() || rip.IsUnspecified() {
			return nil, connectudp.ErrPrivateTargetDenied
		}
		out = append(out, rip)
	}
	return out, nil
}

// ResolveTCPTargetAddrsForDial resolves hostname targets and orders addresses IPv4-first.
// IP literals return a single-element slice. With allowPrivateTargets and a non-IP host,
// returns nil addrs (caller dials hostname via OnwardTCPDialAddr).
func ResolveTCPTargetAddrsForDial(ctx context.Context, host string, allowPrivateTargets bool) ([]netip.Addr, error) {
	trimmedHost := strings.Trim(strings.TrimSpace(host), "[]")
	if allowPrivateTargets {
		if addr, err := netip.ParseAddr(trimmedHost); err == nil {
			return []netip.Addr{addr}, nil
		}
		return nil, nil
	}
	lowerHost := strings.ToLower(trimmedHost)
	if lowerHost == "" || lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".local") {
		return nil, connectudp.ErrPrivateTargetDenied
	}
	addr, err := netip.ParseAddr(trimmedHost)
	if err != nil {
		resolver := net.DefaultResolver
		resolveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		resolved, lookupErr := resolver.LookupNetIP(resolveCtx, "ip", trimmedHost)
		if lookupErr != nil || len(resolved) == 0 {
			return nil, E.New("failed to resolve tcp target")
		}
		public, filterErr := filterPublicTCPAddrs(resolved)
		if filterErr != nil {
			return nil, filterErr
		}
		ordered := OrderResolvedTCPAddrs(public)
		if len(ordered) == 0 {
			return nil, E.New("failed to select resolved tcp target")
		}
		return ordered, nil
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
		return nil, connectudp.ErrPrivateTargetDenied
	}
	return []netip.Addr{addr}, nil
}

// ResolveTCPTargetForDial applies private-target policy before onward TCP dial.
// Deprecated for CONNECT-stream dial path — use ResolveTCPTargetAddrsForDial + serial dial.
func ResolveTCPTargetForDial(ctx context.Context, host string, allowPrivateTargets bool) (string, error) {
	addrs, err := ResolveTCPTargetAddrsForDial(ctx, host, allowPrivateTargets)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		if allowPrivateTargets {
			return strings.Trim(strings.TrimSpace(host), "[]"), nil
		}
		return "", E.New("failed to select resolved tcp target")
	}
	return addrs[0].String(), nil
}

// AllowTCPPort enforces optional allow/deny port lists on CONNECT-stream targets.
func AllowTCPPort(portRaw string, allowList []uint16, denyList []uint16) bool {
	port, err := strconv.Atoi(strings.TrimSpace(portRaw))
	if err != nil || port <= 0 || port > 65535 {
		return false
	}
	for _, denied := range denyList {
		if int(denied) == port {
			return false
		}
	}
	if len(allowList) == 0 {
		return true
	}
	for _, allowed := range allowList {
		if int(allowed) == port {
			return true
		}
	}
	return false
}

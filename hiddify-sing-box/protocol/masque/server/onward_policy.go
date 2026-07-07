package server

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	connectudp "github.com/sagernet/sing-box/transport/masque/connectudp"
)

var (
	// ErrTCPTargetResolveFailed is returned when onward DNS lookup fails (maps to HTTP 502).
	ErrTCPTargetResolveFailed = errors.New("failed to resolve tcp target")
	// ErrTCPTargetSelectFailed is returned when no dialable address remains after policy filter.
	ErrTCPTargetSelectFailed = errors.New("failed to select resolved tcp target")
)

// ConnectStreamResolveHTTPStatus maps onward resolve/policy errors to HTTP status for CONNECT-stream.
func ConnectStreamResolveHTTPStatus(err error) int {
	if errors.Is(err, connectudp.ErrPrivateTargetDenied) {
		return http.StatusForbidden
	}
	return http.StatusBadGateway
}

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

func filterTCPAddrsForDial(resolved []netip.Addr, allowPrivateTargets bool) ([]netip.Addr, error) {
	if allowPrivateTargets {
		out := make([]netip.Addr, 0, len(resolved))
		for _, rip := range resolved {
			if rip.IsUnspecified() {
				continue
			}
			out = append(out, rip)
		}
		return out, nil
	}
	return filterPublicTCPAddrs(resolved)
}

// ResolveTCPTargetAddrsForDial classifies CONNECT-stream targets for onward dial.
//
// Sing-box resolves on the client; MASQUE templates should carry IP literals. IP literals
// return a single-element slice for serial dial + hairpin. Hostnames return nil addrs so
// the handler dials the name via the OS resolver (no MASQUE egress DNS/cache).
func ResolveTCPTargetAddrsForDial(ctx context.Context, host string, allowPrivateTargets bool) ([]netip.Addr, error) {
	_ = ctx
	trimmedHost := strings.Trim(strings.TrimSpace(host), "[]")
	lowerHost := strings.ToLower(trimmedHost)
	if lowerHost == "" || lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".local") {
		if !allowPrivateTargets {
			return nil, connectudp.ErrPrivateTargetDenied
		}
		return nil, nil
	}
	addr, err := netip.ParseAddr(trimmedHost)
	if err == nil {
		if !allowPrivateTargets && (addr.IsLoopback() || addr.IsPrivate() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified()) {
			return nil, connectudp.ErrPrivateTargetDenied
		}
		return []netip.Addr{addr}, nil
	}
	return nil, nil
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
		return "", ErrTCPTargetSelectFailed
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

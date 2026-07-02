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

// ResolveTCPTargetForDial applies private-target policy before onward TCP dial.
func ResolveTCPTargetForDial(ctx context.Context, host string, allowPrivateTargets bool) (string, error) {
	if allowPrivateTargets {
		return strings.Trim(strings.TrimSpace(host), "[]"), nil
	}
	trimmedHost := strings.Trim(strings.TrimSpace(host), "[]")
	lowerHost := strings.ToLower(trimmedHost)
	if lowerHost == "" || lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".local") {
		return "", connectudp.ErrPrivateTargetDenied
	}
	addr, err := netip.ParseAddr(trimmedHost)
	if err != nil {
		resolver := net.DefaultResolver
		resolveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		resolved, lookupErr := resolver.LookupNetIP(resolveCtx, "ip", trimmedHost)
		if lookupErr != nil || len(resolved) == 0 {
			return "", E.New("failed to resolve tcp target")
		}
		var chosen string
		for _, rip := range resolved {
			if rip.IsLoopback() || rip.IsPrivate() || rip.IsMulticast() || rip.IsLinkLocalUnicast() || rip.IsLinkLocalMulticast() || rip.IsUnspecified() {
				return "", connectudp.ErrPrivateTargetDenied
			}
			if chosen == "" {
				chosen = rip.String()
			}
		}
		if chosen == "" {
			return "", E.New("failed to select resolved tcp target")
		}
		return chosen, nil
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
		return "", connectudp.ErrPrivateTargetDenied
	}
	return addr.String(), nil
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

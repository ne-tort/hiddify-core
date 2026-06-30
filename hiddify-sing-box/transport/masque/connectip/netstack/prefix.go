package netstack

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultLocalPrefixWait = 6 * time.Second

var (
	localPrefixWaitEnvCache struct {
		mu    sync.Mutex
		done  bool
		value time.Duration
	}
)

func parseLocalPrefixWaitFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC"))
	if raw == "" {
		return defaultLocalPrefixWait
	}
	sec, err := strconv.Atoi(raw)
	if err != nil || sec < 0 || sec > 60 {
		return defaultLocalPrefixWait
	}
	return time.Duration(sec) * time.Second
}

// LocalPrefixWait bounds LocalPrefixes on the CONNECT-IP conn before falling back
// to synthetic 198.18.0.1. Env is read once per process (MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC).
func LocalPrefixWait() time.Duration {
	localPrefixWaitEnvCache.mu.Lock()
	defer localPrefixWaitEnvCache.mu.Unlock()
	if !localPrefixWaitEnvCache.done {
		localPrefixWaitEnvCache.value = parseLocalPrefixWaitFromEnv()
		localPrefixWaitEnvCache.done = true
	}
	return localPrefixWaitEnvCache.value
}

// ResetLocalPrefixWaitEnvCache clears the prefix-wait env cache (tests only).
func ResetLocalPrefixWaitEnvCache() {
	localPrefixWaitEnvCache.mu.Lock()
	defer localPrefixWaitEnvCache.mu.Unlock()
	localPrefixWaitEnvCache.done = false
}

// LocalPrefixWaitForSession bounds LocalPrefixes blocking when the CONNECT-IP
// snapshot is empty. When the device profile carries a sane tunnel-local, prefer a short tail wait.
func LocalPrefixWaitForSession(profileV4, profileV6 netip.Addr) time.Duration {
	wait := LocalPrefixWait()
	hasProfile := profileV4.Is4() || (profileV6.Is6() && !profileV6.Is4In6())
	if !hasProfile {
		return wait
	}
	const capWhenProfileTrusted = 2 * time.Second
	if wait > capWhenProfileTrusted {
		return capWhenProfileTrusted
	}
	return wait
}

// BogusProfileMasqueIfaceAddr reports addresses that must not be used as the gVisor
// CONNECT-IP "client" source (well-known Cloudflare edge ranges, not WARP tunnel locals).
func BogusProfileMasqueIfaceAddr(addr netip.Addr) bool {
	if !addr.IsValid() || addr.IsUnspecified() {
		return true
	}
	if addr.Is4() {
		b := addr.As4()
		switch {
		case b[0] == 162 && b[1] >= 158 && b[1] <= 159:
			return true
		case b[0] == 172 && b[1] >= 64 && b[1] <= 71:
			return true
		case b[0] == 104 && b[1] >= 16 && b[1] <= 31:
			return true
		default:
			return false
		}
	}
	if addr.Is6() && !addr.Is4In6() {
		if p, err := netip.ParsePrefix("2606:4700::/32"); err == nil && p.Contains(addr) {
			return true
		}
	}
	return false
}

// ParseProfileInterfaceAddress parses a device profile tunnel-local address field.
func ParseProfileInterfaceAddress(raw string) netip.Addr {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}
	}
	if strings.Contains(raw, "/") {
		if pfx, err := netip.ParsePrefix(raw); err == nil {
			addr := pfx.Addr().Unmap()
			if addr.IsValid() && !addr.IsUnspecified() {
				return addr
			}
		}
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}
	}
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() {
		return netip.Addr{}
	}
	if BogusProfileMasqueIfaceAddr(addr) {
		return netip.Addr{}
	}
	return addr
}

// PrefixPreferredAddress returns a host address from an ADDRESS_ASSIGN prefix.
func PrefixPreferredAddress(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	if !addr.IsValid() {
		return netip.Addr{}
	}
	if addr.IsUnspecified() {
		return netip.Addr{}
	}
	return addr
}

// PrefixSource exposes ADDRESS_ASSIGN snapshots from connect-ip-go.
type PrefixSource interface {
	CurrentAssignedPrefixes() []netip.Prefix
	LocalPrefixes(ctx context.Context) ([]netip.Prefix, error)
}

// SessionPrefixWait returns the env/profile-local wait used by CONNECT-IP TCP netstack
// LocalPrefixes blocking. Warp bootstrap passive waits derive from the same helper so
// MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC stays consistent.
func SessionPrefixWait(profileLocalIPv4, profileLocalIPv6 string) time.Duration {
	return LocalPrefixWaitForSession(
		ParseProfileInterfaceAddress(profileLocalIPv4),
		ParseProfileInterfaceAddress(profileLocalIPv6),
	)
}

// WaitForNonEmptyAssignedPrefixes waits for a non-empty ADDRESS_ASSIGN snapshot.
func WaitForNonEmptyAssignedPrefixes(src PrefixSource, wait time.Duration) ([]netip.Prefix, error) {
	if src == nil {
		return nil, errors.New("connectip: prefix source is nil")
	}
	if prefixes := src.CurrentAssignedPrefixes(); len(prefixes) > 0 {
		return prefixes, nil
	}
	if wait <= 0 {
		return nil, context.DeadlineExceeded
	}

	deadline := time.Now().Add(wait)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		ctx, cancel := context.WithTimeout(context.Background(), remaining)
		prefixes, err := src.LocalPrefixes(ctx)
		cancel()
		if len(prefixes) > 0 {
			return prefixes, nil
		}
		if err == nil {
			continue
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			if prefixes := src.CurrentAssignedPrefixes(); len(prefixes) > 0 {
				return prefixes, nil
			}
			if time.Now().Before(deadline) {
				continue
			}
			return nil, context.DeadlineExceeded
		}
		return nil, err
	}
}

func syntheticConnectIPPlaceholder(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	if addr == netip.MustParseAddr("198.18.0.1") {
		return true
	}
	return addr == netip.MustParseAddr("fd00::1")
}

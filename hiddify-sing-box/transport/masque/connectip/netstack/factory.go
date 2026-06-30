package netstack

import (
	"context"
	"net/netip"
)

// Bootstrap carries CONNECT-IP session metadata for TCP netstack factory bootstrap.
type Bootstrap struct {
	PrefixSource       PrefixSource
	ProfileLocalIPv4   string
	ProfileLocalIPv6   string
	DatagramCeiling    int
	OverlayH2          bool
	TCPDatagramSlack   int
	DatagramCeilingMax int
}

// Factory constructs CONNECT-IP TCP netstacks from packet sessions.
type Factory struct{}

// DefaultFactory is the production CONNECT-IP TCP netstack factory.
var DefaultFactory Factory

// New builds a CONNECT-IP TCP netstack with session bootstrap metadata.
func (Factory) New(ctx context.Context, session PacketSession, boot Bootstrap) (*Netstack, error) {
	return NewFromBootstrap(ctx, session, boot, NetstackOptions{})
}

// NewFromBootstrap builds the live CONNECT-IP TCP netstack with optional egress hooks.
func NewFromBootstrap(ctx context.Context, session PacketSession, boot Bootstrap, extra NetstackOptions) (*Netstack, error) {
	defaultV4 := netip.MustParseAddr("198.18.0.1")
	defaultV6 := netip.MustParseAddr("fd00::1")
	localV4 := defaultV4
	localV6 := defaultV6
	mtu := defaultDatagramCeilingMax()
	ceilingMax := boot.DatagramCeilingMax
	if ceilingMax <= 0 {
		ceilingMax = defaultDatagramCeilingMax()
	}
	profileV4 := ParseProfileInterfaceAddress(boot.ProfileLocalIPv4)
	profileV6 := ParseProfileInterfaceAddress(boot.ProfileLocalIPv6)
	var prefixV4, prefixV6 netip.Addr
	if boot.PrefixSource != nil {
		if boot.DatagramCeiling > 0 {
			if boot.DatagramCeiling < 1280 {
				mtu = 1280
			} else if boot.DatagramCeiling > ceilingMax {
				mtu = ceilingMax
			} else {
				mtu = boot.DatagramCeiling
			}
			if boot.OverlayH2 {
				mtu = h2NetstackMTU(mtu)
			} else {
				slack := boot.TCPDatagramSlack
				if slack <= 0 {
					slack = datagramSlack()
				}
				if mtu > slack+576 {
					mtu -= slack
				}
			}
		}
		prefixes := boot.PrefixSource.CurrentAssignedPrefixes()
		if len(prefixes) == 0 {
			wait := LocalPrefixWaitForSession(profileV4, profileV6)
			prefixes, _ = WaitForNonEmptyAssignedPrefixes(boot.PrefixSource, wait)
			if len(prefixes) == 0 {
				prefixes = boot.PrefixSource.CurrentAssignedPrefixes()
			}
		}
		if len(prefixes) > 0 {
			for _, prefix := range prefixes {
				if !prefix.IsValid() {
					continue
				}
				addr := PrefixPreferredAddress(prefix)
				if !addr.IsValid() {
					continue
				}
				if addr.Is4() && !prefixV4.IsValid() {
					prefixV4 = addr
				}
				if addr.Is6() && !addr.Is4In6() && !prefixV6.IsValid() {
					prefixV6 = addr
				}
			}
		}
	}
	if prefixV4.Is4() {
		localV4 = prefixV4
	} else if profileV4.Is4() {
		localV4 = profileV4
	}
	if prefixV6.Is6() {
		localV6 = prefixV6
	} else if profileV6.Is6() {
		localV6 = profileV6
	}
	ns, err := NewNetstack(ctx, session, NetstackOptions{
		LocalIPv4:             localV4,
		LocalIPv6:             localV6,
		MTU:                   mtu,
		OnEgressBatchComplete: extra.OnEgressBatchComplete,
	})
	if err != nil {
		return nil, err
	}
	if boot.PrefixSource != nil {
		ns.ReconcileLocalFromAssignedPrefixes(boot.PrefixSource.CurrentAssignedPrefixes())
	}
	return ns, nil
}

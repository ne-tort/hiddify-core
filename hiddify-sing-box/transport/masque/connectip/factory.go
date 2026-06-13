package connectip

import (
	"context"
	"net/netip"
)

// TCPNetstackFactory constructs a CONNECT-IP TCP netstack for a packet session.
type TCPNetstackFactory interface {
	New(ctx context.Context, session PacketSession, bootstrap SessionBootstrap) (TCPNetstack, error)
}

// DefaultTCPNetstackFactory is the production CONNECT-IP TCP netstack factory.
var DefaultTCPNetstackFactory TCPNetstackFactory = tcpNetstackFactory{}

type tcpNetstackFactory struct{}

// NewProductionTCPNetstack builds the live CONNECT-IP TCP netstack with optional egress hooks.
func NewProductionTCPNetstack(ctx context.Context, session PacketSession, boot SessionBootstrap, hooks NetstackOptions) (TCPNetstack, error) {
	return tcpNetstackFactory{}.newWithBootstrap(ctx, session, boot, hooks)
}

func (f tcpNetstackFactory) New(ctx context.Context, session PacketSession, boot SessionBootstrap) (TCPNetstack, error) {
	return f.newWithBootstrap(ctx, session, boot, NetstackOptions{})
}

func (f tcpNetstackFactory) newWithBootstrap(ctx context.Context, session PacketSession, boot SessionBootstrap, extra NetstackOptions) (TCPNetstack, error) {
	defaultV4 := netip.MustParseAddr("198.18.0.1")
	defaultV6 := netip.MustParseAddr("fd00::1")
	localV4 := defaultV4
	localV6 := defaultV6
	mtu := DefaultDatagramCeilingMax
	ceilingMax := boot.DatagramCeilingMax
	if ceilingMax <= 0 {
		ceilingMax = DefaultDatagramCeilingMax
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
				mtu = H2NetstackMTU(mtu)
			} else {
				slack := boot.TCPDatagramSlack
				if slack <= 0 {
					slack = DatagramSlack
				}
				if mtu > slack+576 {
					mtu -= slack
				}
			}
		}
		prefixes := boot.PrefixSource.CurrentAssignedPrefixes()
		if NetstackDebugEnabled() {
			w := LocalPrefixWait()
			if len(prefixes) == 0 {
				w = LocalPrefixWaitForSession(profileV4, profileV6)
			}
			netstackDebugf("masque connect_ip netstack: CurrentAssignedPrefixes count=%d local_prefix_wait_sec=%d", len(prefixes), int(w.Seconds()))
		}
		if len(prefixes) == 0 {
			wait := LocalPrefixWaitForSession(profileV4, profileV6)
			var err error
			prefixes, err = WaitForNonEmptyAssignedPrefixes(boot.PrefixSource, wait)
			if NetstackDebugEnabled() {
				netstackDebugf("masque connect_ip netstack: LocalPrefixes after wait count=%d err=%v", len(prefixes), err)
			}
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
	if NetstackDebugEnabled() {
		netstackDebugf("masque connect_ip netstack: chosen localIPv4=%s localIPv6=%s mtu=%d prefixV4=%v prefixV6=%v profileV4=%v profileV6=%v",
			localV4, localV6, mtu, prefixV4.IsValid(), prefixV6.IsValid(), profileV4.IsValid(), profileV6.IsValid())
	}
	ns, err := NewNetstack(ctx, session, NetstackOptions{
		LocalIPv4:        localV4,
		LocalIPv6:        localV6,
		MTU:              mtu,
		OnOutboundQueued: extra.OnOutboundQueued,
		OutboundQueueMetrics: extra.OutboundQueueMetrics,
	})
	if err != nil {
		return nil, err
	}
	if boot.PrefixSource != nil {
		ns.ReconcileLocalFromAssignedPrefixes(boot.PrefixSource.CurrentAssignedPrefixes())
	}
	return ns, nil
}

package tun

import (
	"context"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	singtun "github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
)

// resolveL3OverlayNativeOutbound returns outbound implementing native CONNECT-IP L3 wire (PROD-1).
func resolveL3OverlayNativeOutbound(
	outboundManager adapter.OutboundManager,
	tag string,
) (L3OverlayNativeOutbound, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return nil, E.New("tun: l3_overlay_outbound tag empty")
	}
	ob, ok := outboundManager.Outbound(tag)
	if !ok {
		return nil, E.New("tun: l3_overlay_outbound not found: ", tag)
	}
	wire, ok := ob.(L3OverlayNativeOutbound)
	if !ok {
		return nil, E.New("tun: outbound ", tag, " does not implement native CONNECT-IP L3 wire")
	}
	return wire, nil
}

func (t *Inbound) waitL3OverlayOutboundReady(ctx context.Context, ob adapter.Outbound) error {
	ready, ok := ob.(interface{ IsReady() bool })
	if !ok {
		return nil
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ready.IsReady() {
			return nil
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-ticker.C:
		}
	}
}

func (t *Inbound) tryWireNativeConnectIPL3(
	ctx context.Context,
	tunIf singtun.Tun,
	ob adapter.Outbound,
) ([]netip.Prefix, func([]byte) error, func(error), bool, error) {
	wireOut, ok := ob.(L3OverlayNativeOutbound)
	if !ok {
		return nil, nil, nil, false, nil
	}
	wireLocal := t.l3OverlaySocksDest.Addr
	if !wireLocal.IsValid() {
		wireLocal = netip.MustParseAddr("198.18.0.1")
	}
	tunHost := t.l3OverlayTunHost
	if !tunHost.IsValid() {
		tunHost = wireLocal
	}
	wire, wired, err := wireOut.WireConnectIPNativeL3(ctx, tunIf, t.l3OverlayPrefixes, tunHost, wireLocal)
	if err != nil {
		return nil, nil, nil, false, err
	}
	if !wired || wire == nil {
		return nil, nil, nil, false, nil
	}
	t.l3OverlayNativeStart = wire.StartIngress
	t.l3OverlayNativeStop = wire.Stop
	t.l3OverlayNativeBindIngress = wire.BindStackIngress
	log.Printf("connect_ip native L3 overlay wired (prod inbound)")
	return wire.Prefixes, wire.Send, wire.SendErr, true, nil
}

// firstTunInet4 picks the first TUN inet4 address contained in overlay route prefixes.
func firstTunInet4(inet4 []netip.Prefix, routePrefixes []netip.Prefix) netip.Addr {
	for _, ap := range inet4 {
		a := ap.Addr().Unmap()
		if !a.Is4() {
			continue
		}
		for _, rp := range routePrefixes {
			if rp.Contains(a) {
				return a
			}
		}
	}
	return netip.Addr{}
}

func l3OverlayAddr(addr netip.Addr, prefixes []netip.Prefix) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

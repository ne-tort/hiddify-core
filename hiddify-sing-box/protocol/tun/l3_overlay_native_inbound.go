package tun

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/service"
	E "github.com/sagernet/sing/common/exceptions"
)

func resolveL3OverlayNativeOutboundByTag(ctx context.Context, tag string) L3OverlayNativeOutbound {
	if tag == "" {
		return nil
	}
	if epManager := service.FromContext[adapter.EndpointManager](ctx); epManager != nil {
		if ep, ok := epManager.Get(tag); ok {
			if native, ok := ep.(L3OverlayNativeOutbound); ok {
				return native
			}
		}
	}
	if obManager := service.FromContext[adapter.OutboundManager](ctx); obManager != nil {
		if ob, ok := obManager.Outbound(tag); ok {
			if native, ok := ob.(L3OverlayNativeOutbound); ok {
				return native
			}
		}
	}
	return nil
}

func (t *Inbound) resolveL3OverlayNativeOutbound(ob interface{}) L3OverlayNativeOutbound {
	if native, ok := ob.(L3OverlayNativeOutbound); ok {
		return native
	}
	tag := t.l3OverlayOutboundTag
	if tag == "" {
		return nil
	}
	return resolveL3OverlayNativeOutboundByTag(t.ctx, tag)
}

func (t *Inbound) tryWireNativeConnectIPL3(
	ctx context.Context,
	tunIf tun.Tun,
	ob interface{},
) (prefixes []netip.Prefix, send func([]byte) error, sendErr func(error), ok bool, err error) {
	native := t.resolveL3OverlayNativeOutbound(ob)
	if native == nil {
		return nil, nil, nil, false, nil
	}
	wireLocal := t.l3OverlaySocksDest.Addr
	if !wireLocal.IsValid() {
		wireLocal = netip.MustParseAddr("198.18.0.1")
	}
	// usque WaterAdapter: TUN host = CONNECT-IP assigned local (configure tun address = profile_local_ipv4).
	tunHost := firstTunInet4Host(t.tunOptions)
	if !tunHost.IsValid() {
		tunHost = wireLocal
	}
	wire, wired, err := native.WireConnectIPNativeL3(ctx, tunIf, t.l3OverlayPrefixes, tunHost, wireLocal)
	if err != nil || !wired || wire == nil {
		return nil, nil, nil, false, err
	}
	t.l3OverlayNativeStop = wire.Stop
	t.l3OverlayNativeStart = wire.StartIngress
	t.l3OverlayNativeBindIngress = wire.BindStackIngress
	if len(wire.Prefixes) > 0 {
		prefixes = wire.Prefixes
	} else {
		prefixes = t.l3OverlayPrefixes
	}
	return prefixes, wire.Send, wire.SendErr, true, nil
}

func (t *Inbound) waitL3OverlayOutboundReady(ctx context.Context, ob adapter.Outbound) error {
	ready, ok := ob.(interface{ IsReady() bool })
	if !ok {
		return nil
	}
	deadline := time.Now().Add(25 * time.Second)
	for {
		if ready.IsReady() {
			return nil
		}
		if time.Now().After(deadline) {
			return E.New("l3 overlay outbound not ready")
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func firstTunInet4Host(opts tun.Options) netip.Addr {
	for _, p := range opts.Inet4Address {
		if a := p.Addr().Unmap(); a.Is4() {
			return a
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

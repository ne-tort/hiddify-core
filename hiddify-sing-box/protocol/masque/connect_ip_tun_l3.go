package masque

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/protocol/tun"
	CM "github.com/sagernet/sing-box/common/masque"
	TM "github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	singtun "github.com/sagernet/sing-tun"
)

var _ tun.L3OverlayNativeOutbound = (*Endpoint)(nil)

// WireConnectIPNativeL3 wires ARCH-2 connect_ip L3 (WritePacket + FlushEgressBatch) for tun inbound.
func (e *Endpoint) WireConnectIPNativeL3(
	ctx context.Context,
	tunIf singtun.Tun,
	routePrefixes []netip.Prefix,
	tunHost netip.Addr,
	wireLocal netip.Addr,
) (*tun.L3OverlayNativeWire, bool, error) {
	if !TM.ConnectIPTunNativeL3Eligible(e.options.TransportMode, e.options.TCPTransport) {
		return nil, false, nil
	}
	rt, err := e.waitRuntimeReady(ctx)
	if err != nil {
		return nil, false, err
	}
	if rt == nil {
		return nil, false, E.New("masque endpoint not ready for connect_ip native L3")
	}
	sessProvider, ok := rt.(interface {
		MasqueClientSession() TM.ClientSession
	})
	if !ok {
		return nil, false, nil
	}
	sess := sessProvider.MasqueClientSession()
	if sess == nil {
		return nil, false, E.New("masque client session nil")
	}
	prefixes, send, sendErr, startIngress, bindStackIngress, stop, err := TM.ConnectIPTunNativeL3(ctx, tunIf, sess, routePrefixes, tunHost, wireLocal)
	if err != nil {
		return nil, false, err
	}
	return &tun.L3OverlayNativeWire{
		Prefixes:         prefixes,
		Send:             send,
		SendErr:          sendErr,
		StartIngress:     startIngress,
		BindStackIngress: bindStackIngress,
		Stop:             stop,
	}, true, nil
}

// ResetConnectIPTCPAfterShortRelay resets cached connect_ip TCP netstack after a short CM/tun relay.
func (e *Endpoint) ResetConnectIPTCPAfterShortRelay() {
	e.mu.RLock()
	rt := e.runtime
	e.mu.RUnlock()
	if rt == nil {
		return
	}
	if r, ok := rt.(interface{ ResetConnectIPTCPAfterShortRelay() }); ok {
		r.ResetConnectIPTCPAfterShortRelay()
	}
}

// WarmConnectIPTCPAfterShortRelay primes connect_ip TCP ingress after a short CM/tun relay.
func (e *Endpoint) WarmConnectIPTCPAfterShortRelay(ctx context.Context, dest M.Socksaddr) {
	e.mu.RLock()
	rt := e.runtime
	e.mu.RUnlock()
	if rt == nil {
		return
	}
	if w, ok := rt.(interface {
		WarmConnectIPTCPAfterShortRelay(context.Context, M.Socksaddr)
	}); ok {
		w.WarmConnectIPTCPAfterShortRelay(ctx, dest)
	}
}

// ConnectIPNativeL3Active reports whether the outbound uses native L3 overlay (skip CM reset/warm).
func (e *Endpoint) ConnectIPNativeL3Active() bool {
	e.mu.RLock()
	rt := e.runtime
	e.mu.RUnlock()
	if rt == nil {
		return false
	}
	if r, ok := rt.(interface{ ConnectIPNativeL3Active() bool }); ok {
		return r.ConnectIPNativeL3Active()
	}
	return false
}

func (e *Endpoint) waitRuntimeReady(ctx context.Context) (CM.Runtime, error) {
	deadline := time.Now().Add(25 * time.Second)
	for {
		e.mu.RLock()
		rt := e.runtime
		ready := rt != nil && rt.IsReady()
		e.mu.RUnlock()
		if ready {
			return rt, nil
		}
		if err := e.lastStartError(); err != nil {
			return nil, E.Cause(err, "masque startup failed")
		}
		if time.Now().After(deadline) {
			return nil, E.New("masque endpoint not ready for connect_ip native L3")
		}
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

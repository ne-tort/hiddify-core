package masque

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-box/protocol/tun"
	TM "github.com/sagernet/sing-box/transport/masque"
	singtun "github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
)

// PROD-1 endpoint wire API: Endpoint implements tun.L3OverlayNativeOutbound.
var _ tun.L3OverlayNativeOutbound = (*Endpoint)(nil)

// WireConnectIPNativeL3 delegates to transport ConnectIPTunNativeL3.
func (e *Endpoint) WireConnectIPNativeL3(
	ctx context.Context,
	tunIf singtun.Tun,
	routePrefixes []netip.Prefix,
	tunHost netip.Addr,
	wireLocal netip.Addr,
) (wire *tun.L3OverlayNativeWire, ok bool, err error) {
	if !TM.ConnectIPTunNativeL3Eligible(normalizeDataplaneMode(e.options.Mode)) {
		return nil, false, nil
	}
	e.mu.RLock()
	rt := e.runtime
	e.mu.RUnlock()
	if rt == nil || !rt.IsReady() {
		return nil, false, E.New("masque endpoint not ready")
	}
	sessProvider, okSess := rt.(interface{ MasqueClientSession() TM.ClientSession })
	if !okSess {
		return nil, false, E.New("masque runtime missing client session")
	}
	sess := sessProvider.MasqueClientSession()
	if sess == nil {
		return nil, false, E.New("masque client session not ready")
	}
	prefixes, send, sendErr, start, bindStackIngress, stopFn, err := TM.ConnectIPTunNativeL3(
		ctx, tunIf, sess, routePrefixes, tunHost, wireLocal,
	)
	if err != nil {
		return nil, false, err
	}
	return &tun.L3OverlayNativeWire{
		Prefixes:         prefixes,
		Send:             send,
		SendErr:          sendErr,
		StartIngress:     start,
		BindStackIngress: bindStackIngress,
		Stop:             stopFn,
	}, true, nil
}

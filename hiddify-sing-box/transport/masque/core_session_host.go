package masque

import (
	"context"
	"net"
	"net/http"
	"sync"

	connectip "github.com/quic-go/connect-ip-go"
	qmasque "github.com/quic-go/masque-go"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	cipclient "github.com/sagernet/sing-box/transport/masque/connectip/client"
	ciptun "github.com/sagernet/sing-box/transport/masque/connectip/tun"
	cudpclient "github.com/sagernet/sing-box/transport/masque/connectudp/client"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
	"github.com/sagernet/sing-box/transport/masque/httpx"
	"github.com/sagernet/sing-box/transport/masque/session"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
	"sync/atomic"
)

type coreSession struct {
	session.CoreSession
	udpDial func(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error)
	// h2UDPConnectHook substitutes H2 CONNECT-UDP dial for package tests (nil in production).
	h2UDPConnectHook func(ctx context.Context, template *uritemplate.Template, target string) (net.PacketConn, error)
	// dialConnectIPAttemptHook substitutes production CONNECT-IP dial for package tests (nil in production).
	dialConnectIPAttemptHook func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error)
	// listenPacketPreResolveDestinationHook runs after releasing mu on the connect_udp path (tests only).
	listenPacketPreResolveDestinationHook func()
	// listenPacketPostOpenIPSessionUnlockHook runs after Unlock on successful openIPSessionLocked (connect_ip path, tests only).
	listenPacketPostOpenIPSessionUnlockHook func()
	// listenPacketPreChainEndReturnHook runs before returning UDP dial failure when no more hops (connect_udp chain end, tests only).
	listenPacketPreChainEndReturnHook func()
	// dialTCPStreamPreAdvanceHopHook runs after ctx-alive check and before hop advance (tests only; simulates cancel before advanceHop).
	dialTCPStreamPreAdvanceHopHook func()
	// connectIPAckWakeSender substitutes *http3.ClientConn for CONNECT-IP ingress ACK wake in tests (nil in production).
	connectIPAckWakeSender h3t.MasqueWakeSender
	connectIPServerRecycled atomic.Bool
	connectIPNativeL3Active    atomic.Bool
	connectIPNativeL3Reopening atomic.Bool
	connectIPNativeL3Plane     atomic.Pointer[ciptun.NativeL3PlaneSession]
	connectIPNativeL3Netstack  atomic.Pointer[mcip.Netstack]
	connectIPNativeL3EgressSess  atomic.Pointer[l3BridgeEgressSession]
	ipIngressPacketReader      atomic.Pointer[mcip.ClientPacketSession]
	udpPlaneOnce           sync.Once
	udpPlane               *cudpclient.Plane
	ipPlaneOnce            sync.Once
	ipPlane                *cipclient.Plane

	// Live CONNECT-UDP PacketConns for LIFE-3 plane deselect (AUDIT B14 / F3.2).
	udpFlowMu sync.Mutex
	udpFlows  map[*trackedUDPPacketConn]struct{}
}

func (s *coreSession) currentUDPHTTPLayer() string {
	return session.CurrentUDPHTTPLayer(&s.CoreSession)
}

func (s *coreSession) maybeRecordHTTPLayerCacheSuccess(layer string) {
	session.MaybeRecordHTTPLayerCacheSuccess(&s.CoreSession, layer)
}

func (s *coreSession) wireMasqueUDPClientForOverlayLocked() (*qmasque.Client, *uritemplate.Template) {
	return session.WireMasqueUDPClientForOverlayLocked(&s.CoreSession, s.newUDPClient)
}

func (s *coreSession) tryHTTPFallbackSwitch(err error) bool {
	// AUDIT B16 / TASKS F3.4: refuse H3↔H2 pivot while CONNECT-UDP PacketConns are live
	// (fallback closes UDPClient + all H2 transports and would orphan neighbors).
	if s.liveUDPPacketConnCount() > 0 {
		return false
	}
	return session.TryHTTPFallbackSwitch(&s.CoreSession, s.lifecycleHost(), err)
}

func (s *coreSession) tryHTTPFallbackSwitchLockedAssumeMu(err error) bool {
	if s.liveUDPPacketConnCount() > 0 {
		return false
	}
	return session.TryHTTPFallbackSwitchLockedAssumeMu(&s.CoreSession, s.lifecycleHost(), err)
}

func (s *coreSession) resetHTTPFallbackBudgetAfterSuccess() {
	session.ResetHTTPFallbackBudgetAfterSuccess(&s.CoreSession)
}

func (s *coreSession) clearHTTPFallbackConsumedAfterGivingUp() {
	session.ClearHTTPFallbackConsumedAfterGivingUp(&s.CoreSession)
}

func (s *coreSession) quicDialWithPolicy(path string) QUICDialFunc {
	return session.QuicDialWithPolicy(path, s.Options.QUICDial)
}

func (s *coreSession) Capabilities() CapabilitySet {
	return session.OverlayCapabilitySet(s.Caps, s.currentUDPHTTPLayer())
}

func (s *coreSession) advanceHop() bool {
	return session.AdvanceHop(&s.CoreSession)
}

func (s *coreSession) dialDirectTCP(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return session.DialDirectTCP(ctx, nil, network, destination)
}

func (s *coreSession) getTCPRoundTripper(defaultTransport http.RoundTripper) http.RoundTripper {
	// No s.Mu here: CONNECT-IP (openIPSessionLocked) and dialConnectIPTCP hold s.Mu across the dial.
	if rt := s.TCPRoundTripper; rt != nil {
		return rt
	}
	return defaultTransport
}

// BindHTTPLayerHooks wires cross-path HTTP layer hooks (UDP dial, CONNECT-IP attempt, TCP round tripper).
func (s *coreSession) BindHTTPLayerHooks(layerName string, hooks httpx.HookFuncs) {
	httpx.ApplyHookFuncs(
		func(layer string) { s.UDPHTTPLayer.Store(layer) },
		func(hook func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error)) {
			s.dialConnectIPAttemptHook = hook
		},
		func(hook func(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error)) {
			s.udpDial = hook
		},
		func(rt http.RoundTripper) { s.TCPRoundTripper = rt },
		layerName,
		hooks,
	)
}

// lifecycleHost implements session.LifecycleHost / ConnectIPTeardownHost for coreSession (W-IP-3 PR4).
type lifecycleHost struct {
	s *coreSession
}

func (s *coreSession) lifecycleHost() lifecycleHost {
	return lifecycleHost{s: s}
}

func (h lifecycleHost) CancelConnectIPIngress() {
	h.s.ipPlaneHost().CancelConnectIPIngress()
}

func (h lifecycleHost) JoinConnectIPIngress() {
	h.s.ipPlaneHost().JoinConnectIPIngress()
}

func (h lifecycleHost) ClearPreTCPNetstackIngress() {
	h.s.ipPlaneHost().ClearPreTCPNetstackIngress()
}

func (h lifecycleHost) ClearIPIngressPacketReader() {
	h.s.ipPlaneHost().ClearIPIngressPacketReader()
}

func (h lifecycleHost) EmitObservabilityEvent(name string) {
	h.s.ipPlaneHost().EmitObservabilityEvent(name)
}

func (h lifecycleHost) IncConnectIPSessionReset(reason string) {
	h.s.ipPlaneHost().IncConnectIPSessionReset(reason)
}

func (h lifecycleHost) BuildHopTemplates() (udp, ip, tcp *uritemplate.Template, err error) {
	return buildTemplates(h.s.Options)
}

func (h lifecycleHost) CloseUDPClient() {
	h.s.udpPlaneHost().CloseUDPClient()
}

func (h lifecycleHost) CloseLiveConnectUDPPacketConns() {
	h.s.closeLiveUDPPacketConns()
}

func (h lifecycleHost) ResetIPH3TransportLockedAssumeMu() {
	h.s.ipPlaneHost().ResetIPH3TransportLockedAssumeMu()
}

func (h lifecycleHost) ResetH2UDPTransportLockedAssumeMu() {
	h.s.udpPlaneHost().ResetH2UDPTransportLockedAssumeMu()
}

func (h lifecycleHost) CloseAllH2ClientTransports() {
	h.s.closeAllH2ClientTransports()
}

func (h lifecycleHost) CloseH2MasqueClientTransport(tr *http2.Transport) {
	h2c.CloseClientTransport(tr)
}

func (h lifecycleHost) StopConnectIPNativeL3Plane() {
	h.s.stopConnectIPNativeL3Dataplane()
}

func (s *coreSession) Close() error {
	return session.LifecycleClose(&s.CoreSession, s.lifecycleHost())
}

func (s *coreSession) resetHopTemplates() error {
	return session.ResetHopTemplates(&s.CoreSession, s.lifecycleHost())
}

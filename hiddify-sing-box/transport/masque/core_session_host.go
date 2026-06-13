package masque

import (
	"context"
	"net"
	"net/http"

	connectip "github.com/quic-go/connect-ip-go"
	qmasque "github.com/quic-go/masque-go"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
	"github.com/sagernet/sing-box/transport/masque/session"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
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
	ipIngressPacketReader atomic.Pointer[mcip.ClientPacketSession]
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
	return session.TryHTTPFallbackSwitch(&s.CoreSession, s.lifecycleHost(), err)
}

func (s *coreSession) tryHTTPFallbackSwitchLockedAssumeMu(err error) bool {
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

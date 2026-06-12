package masque

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/netip"
	"strings"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/sagernet/sing-box/transport/masque/session"
	"github.com/yosida95/uritemplate/v3"
)

type ipPlaneHost struct {
	s *coreSession
}

type connectIPSameHopDialHost struct {
	s *coreSession
}

type connectIPAttemptDialHost struct {
	s *coreSession
}

func (h connectIPAttemptDialHost) Hook() func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
	return h.s.dialConnectIPAttemptHook
}

func (h connectIPAttemptDialHost) OnSuccess(useHTTP2 bool) {
	dialAddr := connectIPOverlayDialAddr(h.s.Options)
	if useHTTP2 {
		h.s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH2)
		log.Printf("masque_http_layer_chosen layer=h2 tag=%s connect_ip=1 dial=%s", strings.TrimSpace(h.s.Options.Tag), dialAddr)
	} else {
		h.s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH3)
		log.Printf("masque_http_layer_chosen layer=h3 tag=%s connect_ip=1 dial=%s", strings.TrimSpace(h.s.Options.Tag), dialAddr)
	}
	h.s.resetHTTPFallbackBudgetAfterSuccess()
}

func (h connectIPAttemptDialHost) OnCtxCanceled() {
	h.s.clearHTTPFallbackConsumedAfterGivingUp()
}

func (h connectIPAttemptDialHost) Tag() string {
	return h.s.Options.Tag
}

func (h connectIPAttemptDialHost) WarpConnectIPProtocol() string {
	return h.s.Options.WarpConnectIPProtocol
}

func (h connectIPAttemptDialHost) TemplateIP() *uritemplate.Template {
	return h.s.TemplateIP
}

func (h connectIPAttemptDialHost) PrimaryDialHost() string {
	return masqueQuicDialCandidateHost(h.s.Options)
}

func (h connectIPAttemptDialHost) WarpAlternateHost(primary string) string {
	return warpMasqueH2AlternateDialHost(primary)
}

func (h connectIPAttemptDialHost) IsExtendedConnectUnsupported(err error) bool {
	return isMasqueH2ExtendedConnectUnsupportedByPeer(err)
}

func (h connectIPAttemptDialHost) EnsureH2Transport(ctx context.Context) (http.RoundTripper, error) {
	return h.s.ensureH2UDPTransport(ctx)
}

func (h connectIPAttemptDialHost) TCPRoundTripper(defaultTransport http.RoundTripper) http.RoundTripper {
	return h.s.getTCPRoundTripper(defaultTransport)
}

func (h connectIPAttemptDialHost) H2DialParams() cip.H2DialParams {
	token := strings.TrimSpace(h.s.Options.ServerToken)
	var basicHdr http.Header
	if u := strings.TrimSpace(h.s.Options.ClientBasicUsername); u != "" {
		token = ""
		basicHdr = make(http.Header)
		basicHdr.Set("Authorization", masqueClientBasicAuthHeader(u, h.s.Options.ClientBasicPassword))
	}
	return cip.H2DialParams{
		BearerToken:           token,
		WarpConnectIPProtocol: h.s.Options.WarpConnectIPProtocol,
		ExtraRequestHeaders:   basicHdr,
	}
}

func (h connectIPAttemptDialHost) BootstrapParams() cip.SessionBootstrapParams {
	return h.s.connectIPBootstrapParams()
}

func (h connectIPAttemptDialHost) DialH2(ctx context.Context) (*connectip.Conn, error) {
	return cip.DialH2Session(ctx, h)
}

func (h connectIPAttemptDialHost) HasTemplateIP() bool {
	return h.s.TemplateIP != nil
}

func (h connectIPAttemptDialHost) ErrNoTemplateIP() error {
	return ErrConnectIPTemplateNotConfigured
}

func (h connectIPAttemptDialHost) LogH3Attempt(dialAddr string) {
	log.Printf("masque_http_layer_attempt layer=h3 tag=%s connect_ip=1 dial=%s", strings.TrimSpace(h.s.Options.Tag), dialAddr)
}

func (h connectIPAttemptDialHost) OpenH3ClientConn(ctx context.Context) (*http3.ClientConn, error) {
	return h.s.openHTTP3ClientConn(ctx)
}

func (h connectIPAttemptDialHost) DialH3WithBootstrap(ctx context.Context, clientConn *http3.ClientConn) (*connectip.Conn, error) {
	token := strings.TrimSpace(h.s.Options.ServerToken)
	var basicHdr http.Header
	if u := strings.TrimSpace(h.s.Options.ClientBasicUsername); u != "" {
		token = ""
		basicHdr = make(http.Header)
		basicHdr.Set("Authorization", masqueClientBasicAuthHeader(u, h.s.Options.ClientBasicPassword))
	}
	return cip.DialH3TunnelWithBootstrap(ctx, clientConn, h.s.TemplateIP, cip.H3DialParams{
		Tag:                   h.s.Options.Tag,
		BearerToken:           token,
		WarpConnectIPProtocol: h.s.Options.WarpConnectIPProtocol,
		ExtraRequestHeaders:   basicHdr,
	}, h.s.connectIPBootstrapParams())
}

func (h connectIPAttemptDialHost) OverlayDialAddr() string {
	return connectIPOverlayDialAddr(h.s.Options)
}

func (h connectIPSameHopDialHost) DialAttempt(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
	return cip.DialAttempt(ctx, connectIPAttemptDialHost{s: h.s}, useHTTP2)
}

func (h connectIPSameHopDialHost) TryHTTPFallbackSwitch(err error) bool {
	return h.s.tryHTTPFallbackSwitchLockedAssumeMu(err)
}

func (h connectIPSameHopDialHost) CurrentOverlayH2() bool {
	return h.s.currentUDPHTTPLayer() == option.MasqueHTTPLayerH2
}

func (h connectIPSameHopDialHost) ResetIPH3Transport() {
	h.s.resetIPH3TransportLockedAssumeMu()
}

func (h connectIPSameHopDialHost) ResetH2UDPTransport() {
	h.s.resetH2UDPTransportLockedAssumeMu()
}

func (s *coreSession) ipPlaneHost() ipPlaneHost {
	return ipPlaneHost{s: s}
}

func (h ipPlaneHost) BeginOpenIPSession() {
	cip.BeginOpenSession(h.s.Options.ConnectIPScopeTarget, h.s.Options.ConnectIPScopeIPProto)
}

func (h ipPlaneHost) ClearHTTPFallbackAfterGiveUp() {
	h.s.clearHTTPFallbackConsumedAfterGivingUp()
}

func (h ipPlaneHost) RecordOpenNotSupported() error {
	return cip.OpenSessionNotSupportedError()
}

func (h ipPlaneHost) CtxDone(ctx context.Context) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return context.Cause(ctx)
	}
	return nil
}

func (h ipPlaneHost) JoinCtxCancel(err error, ctx context.Context) error {
	if ctx.Err() != nil {
		return errors.Join(err, context.Cause(ctx))
	}
	return err
}

func (h ipPlaneHost) CurrentOverlayH2() bool {
	return h.s.currentUDPHTTPLayer() == option.MasqueHTTPLayerH2
}

func (h ipPlaneHost) DialConnectIPOnCurrentHopLocked(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
	return h.s.dialConnectIPOnCurrentHopLocked(ctx, useHTTP2)
}

func (h ipPlaneHost) ReuseIPConnIfPresent(overlayH2 bool) (session.IPPacketSession, bool) {
	if h.s.IPConn == nil {
		return nil, false
	}
	h.s.registerConnectIPAssignedPrefixesListenerLocked(h.s.IPConn)
	if h.s.ipIngressPacketReader.Load() == nil {
		h.s.ipIngressPacketReader.Store(h.s.newConnectIPPacketSession(h.s.IPConn, overlayH2))
	}
	cip.RecordOpenSessionSuccessReuse()
	h.s.resetHTTPFallbackBudgetAfterSuccess()
	return h.s.newConnectIPPacketSession(h.s.IPConn, overlayH2), true
}

func (h ipPlaneHost) OnDialSuccess(conn *connectip.Conn, useHTTP2 bool, startIngress bool) session.IPPacketSession {
	h.s.IPConn = conn
	h.s.registerConnectIPAssignedPrefixesListenerLocked(conn)
	h.s.ipIngressPacketReader.Store(h.s.newConnectIPPacketSession(conn, useHTTP2))
	cip.RecordOpenSessionSuccessNew()
	if startIngress {
		h.s.maybeStartConnectIPIngressLocked()
	}
	return h.s.newConnectIPPacketSession(conn, useHTTP2)
}

func (h ipPlaneHost) AdvanceHop() bool {
	return session.AdvanceHop(&h.s.CoreSession)
}

func (h ipPlaneHost) ResetHopTemplates() error {
	return h.s.resetHopTemplates()
}

func (h ipPlaneHost) RecordOpenFailure(err error) {
	cip.RecordOpenSessionFailure(err)
}

func (h ipPlaneHost) LogDialFailure(err error) {
	serverTokenSet := strings.TrimSpace(h.s.Options.ServerToken) != ""
	warpMTLS := len(h.s.Options.WarpMasqueClientCert.Certificate) > 0
	cip.LogOpenDialFailure(h.s.Options.Server, h.s.Options.ServerPort, serverTokenSet, warpMTLS, err)
}

func (s *coreSession) openIPSessionLocked(ctx context.Context) (IPPacketSession, error) {
	return session.OpenIPSessionLocked(&s.CoreSession, s.ipPlaneHost(), ctx)
}

func (s *coreSession) dialConnectIPHTTP2(ctx context.Context) (*connectip.Conn, error) {
	return cip.DialH2Session(ctx, connectIPAttemptDialHost{s: s})
}

// releaseOpenedConnectIPSessionIfAbandoned tears down CONNECT-IP plane state when openIPSessionLocked
// succeeded but the caller must return an error before the consumer receives a net.PacketConn (e.g.
// context canceled after Unlock). Without this, ipConn would remain attached while the caller saw
// failure — leaking the tunnel and contradicting the next ListenPacket/OpenIPSession attempt.
// Caller must not hold s.Mu.
//
// Call sites: ListenPacket after openIPSessionLocked+Unlock if ctx is done; dialConnectIPTCP if
// netstack factory fails. Do not call after Unlock solely because the dial ctx expired: outbound
// monitoring URL tests use short deadlines; tearing CONNECT-IP here would cancel a healthy session.
func (s *coreSession) closeConnectIPDataplaneLockedAssumeMu() {
	session.CloseConnectIPDataplaneLockedAssumeMu(&s.CoreSession, s.lifecycleHost())
}

func (s *coreSession) releaseOpenedConnectIPSessionIfAbandoned() {
	session.ReleaseOpenedConnectIPSessionIfAbandoned(&s.CoreSession, s.lifecycleHost())
}

func connectIPOverlayDialAddr(opts ClientOptions) string {
	return cip.OverlayDialAddr(cip.OverlayDialParams{
		Server:     opts.Server,
		ServerPort: int(opts.ServerPort),
		DialPeer:   opts.DialPeer,
	})
}

func (s *coreSession) connectIPBootstrapParams() cip.SessionBootstrapParams {
	return cip.NewSessionBootstrapParams(
		s.Options.Tag,
		s.Options.WarpConnectIPProtocol,
		s.Options.ProfileLocalIPv4,
		s.Options.ProfileLocalIPv6,
	)
}

func (s *coreSession) dialConnectIPAttempt(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
	return cip.DialAttempt(ctx, connectIPAttemptDialHost{s: s}, useHTTP2)
}

// dialConnectIPOnCurrentHopLocked runs the same-hop CONNECT-IP sequence used by openIPSessionLocked.
// Caller must hold s.Mu.
func (s *coreSession) dialConnectIPOnCurrentHopLocked(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
	return cip.DialOnCurrentHop(ctx, connectIPSameHopDialHost{s: s}, useHTTP2)
}

func (s *coreSession) registerConnectIPAssignedPrefixesListenerLocked(conn *connectip.Conn) {
	cip.RegisterAssignedPrefixesListener(conn, func(prefixes []netip.Prefix) {
		ns := s.IngressTCPNetstack.Load()
		if ns == nil {
			return
		}
		ns.ReconcileLocalFromAssignedPrefixes(prefixes)
	})
}

func (s *coreSession) newConnectIPPacketSession(conn *connectip.Conn, overlayH2 bool) *cip.ClientPacketSession {
	return cip.NewClientPacketSessionFromParams(cip.SessionPacketParams{
		Conn:              conn,
		DatagramCeiling:   s.ConnectIPDatagramCeiling,
		UDPPayloadHardCap: s.ConnectIPUDPPayloadHardCap,
		TCPDatagramSlack:  s.ConnectIPTCPDatagramSlack,
		PMTUState:         s.ConnectIPPMTUState,
		ProfileLocalIPv4:  s.Options.ProfileLocalIPv4,
		ProfileLocalIPv6:  s.Options.ProfileLocalIPv6,
		OverlayH2:         overlayH2,
		WakeAfterDatagram: s.scheduleConnectIPDatagramSendWake,
	})
}

func (s *coreSession) scheduleConnectIPDatagramSendWake() {
	s.ConnectIPIngressAckWake.Schedule()
	s.flushConnectIPIngressAckWake()
}

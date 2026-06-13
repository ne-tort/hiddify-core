package masque

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"

	connectip "github.com/quic-go/connect-ip-go"
	qmasque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
	"github.com/sagernet/sing-box/transport/masque/httpx"
	"github.com/sagernet/sing-box/transport/masque/session"
	"github.com/yosida95/uritemplate/v3"
)

// G73: merged ip_plane_bridge + ingress_bridge — production CONNECT-IP session host adapters.

type (
	udpIngressSubscriber = cip.UDPIngressSubscriber
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

type connectIPIngressHost struct {
	s *coreSession
}

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

// --- ip plane host (session.IPPlaneHost) ---

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
	auth := cip.DialAuthFromCredentials(h.s.Options.ServerToken, h.s.Options.ClientBasicUsername, h.s.Options.ClientBasicPassword)
	return cip.H2DialParams{
		BearerToken:           auth.BearerToken,
		WarpConnectIPProtocol: h.s.Options.WarpConnectIPProtocol,
		ExtraRequestHeaders:   auth.ExtraRequestHeaders,
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
	return session.ErrConnectIPTemplateNotConfigured
}

func (h connectIPAttemptDialHost) LogH3Attempt(dialAddr string) {
	log.Printf("masque_http_layer_attempt layer=h3 tag=%s connect_ip=1 dial=%s", strings.TrimSpace(h.s.Options.Tag), dialAddr)
}

func (h connectIPAttemptDialHost) OpenH3ClientConn(ctx context.Context) (*http3.ClientConn, error) {
	return h.s.openHTTP3ClientConn(ctx)
}

func (h connectIPAttemptDialHost) DialH3WithBootstrap(ctx context.Context, clientConn *http3.ClientConn) (*connectip.Conn, error) {
	auth := cip.DialAuthFromCredentials(h.s.Options.ServerToken, h.s.Options.ClientBasicUsername, h.s.Options.ClientBasicPassword)
	return cip.DialH3TunnelWithBootstrap(ctx, clientConn, h.s.TemplateIP, cip.H3DialParams{
		Tag:                   h.s.Options.Tag,
		BearerToken:           auth.BearerToken,
		WarpConnectIPProtocol: h.s.Options.WarpConnectIPProtocol,
		ExtraRequestHeaders:   auth.ExtraRequestHeaders,
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
	if overlayH2 {
		h.s.IPHTTPH2Upload = h.s.IPConn.H2IngressUploadWriter()
	} else {
		h.s.IPHTTPH2Upload = nil
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
	if useHTTP2 {
		h.s.IPHTTPH2Upload = conn.H2IngressUploadWriter()
	} else {
		h.s.IPHTTPH2Upload = nil
	}
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

// --- ingress host (connectip.IngressHost) ---

func (h connectIPIngressHost) IngressTransportModeOK() bool {
	tm := strings.TrimSpace(h.s.Options.TransportMode)
	if tm != "" && !strings.EqualFold(tm, "connect_ip") {
		return false
	}
	return h.s.IPConn != nil && h.s.ipIngressPacketReader.Load() != nil
}

func (h connectIPIngressHost) IngressPacketReader() func(ctx context.Context, buf []byte) (int, error) {
	reader := h.s.ipIngressPacketReader.Load()
	if reader == nil {
		return nil
	}
	return reader.ReadPacketWithContext
}

func (h connectIPIngressHost) IngressTCPInstallInflight() bool {
	return h.s.ConnectIPTCPInstallInflight.Load() > 0
}

func (h connectIPIngressHost) IngressTCPNetstack() *connectIPTCPNetstack {
	return h.s.IngressTCPNetstack.Load()
}

func (h connectIPIngressHost) IngressTCPNetstackForInject() *connectIPTCPNetstack {
	return h.s.IngressTCPNetstack.Load()
}

func (h connectIPIngressHost) IngressTCPFastPath(pkt []byte) bool {
	return cip.TCPIngressFastPath(
		pkt,
		h.s.connectIPIngressPlane().UDPSubsEmpty(),
		h.s.IngressTCPNetstack.Load() != nil,
		h.s.ConnectIPTCPInstallInflight.Load() > 0,
	)
}

func (h connectIPIngressHost) IngressDeliverTCPNoFlush(pkt []byte) bool {
	return h.s.deliverConnectIPTCPIngressNoFlush(pkt)
}

func (h connectIPIngressHost) IngressDeliverTCP(pkt []byte) bool {
	ok := h.s.deliverConnectIPTCPIngressNoFlush(pkt)
	h.s.flushConnectIPIngressAckWake()
	return ok
}

func (h connectIPIngressHost) IngressFlushAckWake() {
	h.s.flushConnectIPIngressAckWake()
}

func (h connectIPIngressHost) IngressOnReadFatal(err error) {
	if ns := h.s.IngressTCPNetstack.Load(); ns != nil {
		ns.FailWithError(errors.Join(session.ErrTransportInit, err))
	}
}

func (h connectIPIngressHost) IngressDebugLog(pkt []byte, n int, hasNS bool, inflight bool) {
	if n < 20 {
		return
	}
	log.Printf("masque connect_ip ingress: rx n=%d ver=%d proto=%d ns=%v inflight=%d",
		n, pkt[0]>>4, pkt[9], hasNS, h.s.ConnectIPTCPInstallInflight.Load())
}

func (h connectIPIngressHost) IngressObsEvent(name string) {
	cip.EmitObservabilityEvent(name)
}

func (h connectIPIngressHost) IngressEngineDrop(reason string) {
	cip.IncEngineDropReason(reason)
}

func (h connectIPIngressHost) IngressReadDrop(reason string) {
	cip.IncReadDropReason(reason)
}

func (h connectIPIngressHost) IngressSessionReset(reason string) {
	cip.IncSessionReset(reason)
}

func (s *coreSession) connectIPIngressPlane() *cip.Ingress {
	s.ConnectIPIngressOnce.Do(func() {
		s.ConnectIPIngress = cip.NewIngress(connectIPIngressHost{s: s})
	})
	return s.ConnectIPIngress
}

func (s *coreSession) registerUDPIngressSubscriber() *udpIngressSubscriber {
	sub := s.connectIPIngressPlane().RegisterUDPSubscriber()
	s.maybeStartConnectIPIngress()
	return sub
}

func (s *coreSession) maybeStartConnectIPIngress() {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.maybeStartConnectIPIngressLocked()
}

func (s *coreSession) maybeStartConnectIPIngressLocked() {
	s.connectIPIngressPlane().MaybeStart(s.TCPNetstack != nil)
}

func (s *coreSession) unregisterUDPIngressSubscriber(sub *udpIngressSubscriber) {
	s.connectIPIngressPlane().UnregisterUDPSubscriber(sub)
	s.maybeStopConnectIPIngressIfIdle()
}

func (s *coreSession) maybeStopConnectIPIngressIfIdle() {
	s.Mu.Lock()
	hasTCP := s.TCPNetstack != nil
	s.Mu.Unlock()
	s.connectIPIngressPlane().MaybeStopIfIdle(hasTCP)
}

func (s *coreSession) stopConnectIPIngressGracefully() {
	s.connectIPIngressPlane().StopGracefully()
}

func (s *coreSession) cancelConnectIPIngress() {
	s.connectIPIngressPlane().Cancel()
}

func (s *coreSession) joinConnectIPIngress() {
	s.connectIPIngressPlane().Join()
}

func (s *coreSession) enqueuePreTCPNetstackIngress(pkt []byte) {
	s.connectIPIngressPlane().EnqueuePreTCP(pkt)
}

func (s *coreSession) flushPreTCPNetstackIngress(ns *connectIPTCPNetstack) {
	s.connectIPIngressPlane().FlushPreTCP(ns)
}

func (s *coreSession) clearPreTCPNetstackIngress() {
	s.connectIPIngressPlane().ClearPreTCP()
}

func (s *coreSession) deliverIPv4UDPBridgedIngress(pkt []byte) bool {
	return s.connectIPIngressPlane().DeliverIPv4UDPBridged(pkt)
}

func (s *coreSession) connectIPUDPIngressSubsEmpty() bool {
	return s.connectIPIngressPlane().UDPSubsEmpty()
}

func (s *coreSession) noteConnectIPIngressAckForWake(pkt []byte) {
	s.ConnectIPIngressAckWake.NoteFromPacket(pkt)
}

func (s *coreSession) flushConnectIPIngressAckWake() {
	if !s.ConnectIPIngressAckWake.TakePending() {
		return
	}
	if s.currentUDPHTTPLayer() == option.MasqueHTTPLayerH2 {
		h2c.FlushConnectIPIngressAckWake(s.IPHTTPH2Upload)
		return
	}
	sender := h3t.MasqueWakeSender(s.IPHTTPConn)
	if s.connectIPAckWakeSender != nil {
		sender = s.connectIPAckWakeSender
	}
	h3t.FlushConnectIPIngressAckWake(s.currentUDPHTTPLayer(), sender)
}

func (s *coreSession) deliverConnectIPTCPIngress(pkt []byte) bool {
	ok := s.deliverConnectIPTCPIngressNoFlush(pkt)
	s.flushConnectIPIngressAckWake()
	return ok
}

func (s *coreSession) deliverConnectIPTCPIngressNoFlush(pkt []byte) bool {
	return cip.DeliverTCPIngress(pkt, cip.WireTCPIngressDeliver(
		func() *connectIPTCPNetstack { return s.IngressTCPNetstack.Load() },
		func() bool { return s.ConnectIPTCPInstallInflight.Load() > 0 },
		func() *connectIPTCPNetstack { return s.IngressTCPNetstack.Load() },
		s.enqueuePreTCPNetstackIngress,
		func(pkt []byte, _ *cip.Netstack) { s.noteConnectIPIngressAckForWake(pkt) },
	))
}

package masque

// connectIPPlaneHost implements session.IPPlaneHost and dial hosts for coreSession (W-IP-0 PR2).
// Lives in package masque (not connectip/client) to avoid import cycle with coreSession.
// TCP netstack dial host: connectIPTCPDialHost (W-IP-3 PR2, was connectip_tcp_bridge.go).

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	ciph2 "github.com/sagernet/sing-box/transport/masque/connectip/h2"
	cipclient "github.com/sagernet/sing-box/transport/masque/connectip/client"
	cudph2 "github.com/sagernet/sing-box/transport/masque/connectudp/h2"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/sagernet/sing-box/transport/masque/pathbuild"
	"github.com/sagernet/sing-box/transport/masque/session"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

type ipPlaneHost struct {
	s *coreSession
}

// connectIPSessionPlaneAdapter implements connectip/client.SessionIP (open + lazy ingress).
type connectIPSessionPlaneAdapter struct {
	ipPlaneHost
}

func (s *coreSession) connectIPPlane() *cipclient.Plane {
	s.ipPlaneOnce.Do(func() {
		s.ipPlane = cipclient.NewPlane(connectIPSessionPlaneAdapter{ipPlaneHost: ipPlaneHost{s: s}})
	})
	return s.ipPlane
}

func (a connectIPSessionPlaneAdapter) IngressPlane() *cip.Ingress {
	s := a.ipPlaneHost.s
	s.ConnectIPIngressOnce.Do(func() {
		s.ConnectIPIngress = cip.NewIngress(connectIPIngressHost{s: s})
	})
	return s.ConnectIPIngress
}

type connectIPSameHopDialHost struct {
	s *coreSession
}

type connectIPTCPDialHost struct {
	s *coreSession
}

func (s *coreSession) connectIPTCPDialHost() connectIPTCPDialHost {
	return connectIPTCPDialHost{s: s}
}

func (h connectIPTCPDialHost) ClearHTTPFallbackAfterGiveUp() {
	h.s.clearHTTPFallbackConsumedAfterGivingUp()
}

func (h connectIPTCPDialHost) LockSession()   { h.s.Mu.Lock() }
func (h connectIPTCPDialHost) UnlockSession() { h.s.Mu.Unlock() }

func (h connectIPTCPDialHost) OpenIPSessionLocked(ctx context.Context) (cip.PacketSession, error) {
	return h.s.openIPSessionLocked(ctx)
}

func (h connectIPTCPDialHost) TCPNetstack() cip.TCPNetstack {
	return h.s.TCPNetstack
}

func (h connectIPTCPDialHost) AttachTCPNetstack(ns cip.TCPNetstack) {
	h.s.TCPNetstack = ns
	if impl, ok := ns.(*cip.Netstack); ok {
		h.s.IngressTCPNetstack.Store(impl)
		h.s.flushPreTCPNetstackIngress(impl)
		return
	}
	h.s.IngressTCPNetstack.Store(nil)
}

func (h connectIPTCPDialHost) FlushTCPNetstackIngress(ns cip.TCPNetstack) {
	if impl, ok := ns.(*cip.Netstack); ok {
		h.s.flushPreTCPNetstackIngress(impl)
	}
}

func (h connectIPTCPDialHost) BumpTCPInstallInflight(delta int) {
	h.s.ConnectIPTCPInstallInflight.Add(int32(delta))
}

func (h connectIPTCPDialHost) MaybeStartConnectIPIngressLocked() {
	h.s.maybeStartConnectIPIngressLocked()
}

func (h connectIPTCPDialHost) NewTCPNetstack(ctx context.Context, session cip.PacketSession) (cip.TCPNetstack, error) {
	return cip.NewProductionTCPNetstackFromPacketSession(ctx, session)
}

func (h connectIPTCPDialHost) OnTCPNetstackFactoryError() {
	h.s.clearPreTCPNetstackIngress()
}

func (h connectIPTCPDialHost) RecordTCPNetstackReady(ready bool) {
	session.RecordConnectIPStackReady(ready)
}

func (h connectIPTCPDialHost) ReleaseAbandonedIPSession() {
	h.s.releaseOpenedConnectIPSessionIfAbandoned()
}

func (h connectIPTCPDialHost) ResetStaleConnectIPPlaneLocked() {
	ph := h.s.ipPlaneHost()
	session.CloseConnectIPDataplaneLockedAssumeMu(&h.s.CoreSession, ph)
	ph.ResetIPH3TransportLockedAssumeMu()
	ph.ResetH2UDPTransportLockedAssumeMu()
}

func (s *coreSession) dialConnectIPTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if s.connectIPNativeL3Active.Load() {
		return nil, errors.New("connect-ip native L3: TCP must use gVisor L3 overlay, not dialConnectIPTCP")
	}
	return cip.DialTCP(ctx, s.connectIPTCPDialHost(), destination)
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
	return cudph2.WarpH2AlternateDialHost(primary)
}

func (h connectIPAttemptDialHost) IsExtendedConnectUnsupported(err error) bool {
	return cudph2.IsH2ExtendedConnectUnsupportedByPeer(err)
}

func (h connectIPAttemptDialHost) EnsureH2Transport(ctx context.Context) (http.RoundTripper, error) {
	return h.s.ensureH2UDPTransport(ctx)
}

func (h connectIPAttemptDialHost) TCPRoundTripper(defaultTransport http.RoundTripper) http.RoundTripper {
	return h.s.getTCPRoundTripper(defaultTransport)
}

func (h connectIPAttemptDialHost) H2DialParams() cip.H2DialParams {
	auth := cip.DialAuthFromInput(cip.DialAuthInput{
		ServerToken:                 h.s.Options.ServerToken,
		ClientBasicUsername:         h.s.Options.ClientBasicUsername,
		ClientBasicPassword:         h.s.Options.ClientBasicPassword,
		WarpMasqueDeviceBearerToken: h.s.Options.WarpMasqueDeviceBearerToken,
		WarpMasqueClientCert:        h.s.Options.WarpMasqueClientCert,
	})
	return cip.H2DialParams{
		BearerToken:           auth.BearerToken,
		WarpConnectIPProtocol: h.s.Options.WarpConnectIPProtocol,
		ExtraRequestHeaders:   auth.ExtraRequestHeaders,
		PathObfuscationKey:    pathbuild.ActiveKey(h.s.Options.PathObfuscation),
	}
}

func (h connectIPAttemptDialHost) BootstrapParams() cip.SessionBootstrapParams {
	return h.s.connectIPBootstrapParams()
}

func (h connectIPAttemptDialHost) DialH2(ctx context.Context) (*connectip.Conn, error) {
	return ciph2.DialH2Session(ctx, h)
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
	auth := cip.DialAuthFromInput(cip.DialAuthInput{
		ServerToken:                 h.s.Options.ServerToken,
		ClientBasicUsername:         h.s.Options.ClientBasicUsername,
		ClientBasicPassword:         h.s.Options.ClientBasicPassword,
		WarpMasqueDeviceBearerToken: h.s.Options.WarpMasqueDeviceBearerToken,
		WarpMasqueClientCert:        h.s.Options.WarpMasqueClientCert,
	})
	return cip.DialH3TunnelWithBootstrap(ctx, clientConn, h.s.TemplateIP, cip.H3DialParams{
		Tag:                   h.s.Options.Tag,
		BearerToken:           auth.BearerToken,
		WarpConnectIPProtocol: h.s.Options.WarpConnectIPProtocol,
		ExtraRequestHeaders:   auth.ExtraRequestHeaders,
		PathObfuscationKey:    pathbuild.ActiveKey(h.s.Options.PathObfuscation),
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
	if h.connectIPPlaneStaleLocked() {
		session.CloseConnectIPDataplaneLockedAssumeMu(&h.s.CoreSession, h)
		h.ResetIPH3TransportLockedAssumeMu()
		h.ResetH2UDPTransportLockedAssumeMu()
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
	h.s.ClearConnectIPServerRecycled()
	h.s.resetHTTPFallbackBudgetAfterSuccess()
	return h.s.newConnectIPPacketSession(h.s.IPConn, overlayH2), true
}

func (h ipPlaneHost) connectIPPlaneStaleLocked() bool {
	if ns := h.s.TCPNetstack; ns != nil {
		if te, ok := ns.(interface{ TerminalError() error }); ok {
			if err := te.TerminalError(); err != nil {
				return true
			}
		}
	}
	probeCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var buf [4]byte
	_, err := h.s.IPConn.ReadPacketWithContext(probeCtx, buf[:])
	if errors.Is(err, connectip.ErrTransportUnset) {
		return true
	}
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		// Half-open QUIC may not deliver within probe window; treat as stale when server recycled.
		return h.s.ConnectIPServerGenerationStale()
	}
	return cip.IsBenignEgressTeardownError(err) || errors.Is(err, net.ErrClosed)
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
	h.s.ClearConnectIPServerRecycled()
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
	return s.connectIPPlane().OpenIPSessionLocked(&s.CoreSession, ctx)
}

func (s *coreSession) dialConnectIPHTTP2(ctx context.Context) (*connectip.Conn, error) {
	return ciph2.DialH2Session(ctx, connectIPAttemptDialHost{s: s})
}

func (s *coreSession) closeConnectIPDataplaneLockedAssumeMu() {
	session.CloseConnectIPDataplaneLockedAssumeMu(&s.CoreSession, s.ipPlaneHost())
}

func (s *coreSession) releaseOpenedConnectIPSessionIfAbandoned() {
	session.ReleaseOpenedConnectIPSessionIfAbandoned(&s.CoreSession, s.ipPlaneHost())
}

// closeConnectIPPlane tears down CONNECT-IP while keeping QUIC/session alive (LIFE-3 selector deselect).
func (s *coreSession) closeConnectIPPlane() {
	session.CloseConnectIPPlane(&s.CoreSession, s.lifecycleHost())
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
		WakeAfterDatagram: s.pokeConnectIPEgressSend,
	})
}

func (s *coreSession) pokeConnectIPEgressSend() {
	if s.currentUDPHTTPLayer() == option.MasqueHTTPLayerH2 {
		h2c.FlushConnectIPIngressAckWake(s.IPHTTPH2Upload)
		return
	}
	if s.IPConn != nil {
		s.IPConn.FlushOutgoingDatagramSend()
	}
}

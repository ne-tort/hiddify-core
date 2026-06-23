package masque

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	connectip "github.com/quic-go/connect-ip-go"
	qmasque "github.com/quic-go/masque-go"
	"github.com/sagernet/sing-box/option"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	cudpclient "github.com/sagernet/sing-box/transport/masque/connectudp/client"
	"github.com/sagernet/sing-box/transport/masque/connectudp/split"
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
	ipIngressPacketReader  atomic.Pointer[mcip.ClientPacketSession]
	udpPlaneOnce           sync.Once
	udpPlane               *cudpclient.Plane
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

type connectUDPPlaneHost struct {
	s *coreSession
}

func (s *coreSession) connectUDPPlane() *cudpclient.Plane {
	s.udpPlaneOnce.Do(func() {
		s.udpPlane = cudpclient.NewPlane(connectUDPPlaneHost{s: s})
	})
	return s.udpPlane
}

func (h connectUDPPlaneHost) Tag() string {
	return cudpclient.TrimTag(h.s.Options.Tag)
}

func (h connectUDPPlaneHost) CurrentHTTPLayer() string {
	return h.s.currentUDPHTTPLayer()
}

func (h connectUDPPlaneHost) DialOverHTTP2(ctx context.Context, template *uritemplate.Template, target string) (net.PacketConn, error) {
	return h.s.dialUDPOverHTTP2(ctx, template, target)
}

func (h connectUDPPlaneHost) DialH3(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
	return cudpclient.DialH3Production(ctx, h.s.udpDial, client, template, target)
}

func (h connectUDPPlaneHost) RecordHTTPLayerSuccess(layer string) {
	h.s.maybeRecordHTTPLayerCacheSuccess(layer)
}

func (h connectUDPPlaneHost) ResetHTTPFallbackBudgetAfterSuccess() {
	h.s.resetHTTPFallbackBudgetAfterSuccess()
}

func (h connectUDPPlaneHost) ErrTemplateNotConfigured() error {
	return session.ErrConnectUDPTemplateNotConfigured
}

func (h connectUDPPlaneHost) ObservabilityInput(template *uritemplate.Template, target string) cudpclient.ObservabilityInput {
	opts := h.s.Options
	return cudpclient.ObservabilityInput{
		Template: template,
		Target:   target,
		ResolveDialAddr: func() string {
			portNum := int(opts.ServerPort)
			if portNum <= 0 {
				portNum = 443
			}
			return masqueDialTarget(masqueQuicDialCandidateHost(opts), portNum)
		},
	}
}

func (h connectUDPPlaneHost) ClearHTTPFallbackAfterGiveUp() {
	h.s.clearHTTPFallbackConsumedAfterGivingUp()
}

func (h connectUDPPlaneHost) PreResolveDestinationHook() {
	if hook := h.s.listenPacketPreResolveDestinationHook; hook != nil {
		hook()
	}
}

func (h connectUDPPlaneHost) PreChainEndReturnHook() {
	if hook := h.s.listenPacketPreChainEndReturnHook; hook != nil {
		hook()
	}
}

func (h connectUDPPlaneHost) CtxErr(ctx context.Context) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	return nil
}

func (h connectUDPPlaneHost) JoinCtxCancel(err error, ctx context.Context) error {
	if ctx.Err() != nil {
		return errors.Join(err, context.Cause(ctx))
	}
	return err
}

func (h connectUDPPlaneHost) ResolveDestination(destination M.Socksaddr) (string, error) {
	return resolveDestinationHost(destination)
}

func (h connectUDPPlaneHost) PrepareUDP() (*qmasque.Client, *uritemplate.Template, int, string, error) {
	h.s.Mu.Lock()
	defer h.s.Mu.Unlock()
	if !h.s.Caps.ConnectUDP {
		return nil, nil, 0, "", cudpclient.ErrConnectUDPNotSupported
	}
	if h.s.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
		if h.s.UDPClient == nil {
			h.s.UDPClient = h.NewQUICClient()
		}
	}
	return h.s.UDPClient, h.s.TemplateUDP, h.s.MasqueUDPWriteMax, h.s.currentUDPHTTPLayer(), nil
}

func (h connectUDPPlaneHost) DialUDP(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
	return h.s.dialUDPAddr(ctx, client, template, target)
}

func (h connectUDPPlaneHost) TryHTTPFallbackSwitch(err error) bool {
	return h.s.tryHTTPFallbackSwitch(err)
}

func (h connectUDPPlaneHost) RewireUDPAfterFallback() (*qmasque.Client, *uritemplate.Template) {
	h.s.Mu.Lock()
	defer h.s.Mu.Unlock()
	return h.s.wireMasqueUDPClientForOverlayLocked()
}

func (h connectUDPPlaneHost) RefreshUDPAfterDialFailure(prevClient *qmasque.Client) (*qmasque.Client, *uritemplate.Template) {
	h.s.Mu.Lock()
	defer h.s.Mu.Unlock()
	if h.s.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
		if h.s.UDPClient == prevClient && h.s.UDPClient != nil {
			_ = h.s.UDPClient.Close()
			h.s.UDPClient = h.NewQUICClient()
		} else if h.s.UDPClient == nil {
			h.s.UDPClient = h.NewQUICClient()
		}
	} else {
		h.s.resetH2UDPTransportLockedAssumeMu()
	}
	return h.s.UDPClient, h.s.TemplateUDP
}

func (h connectUDPPlaneHost) AdvanceHopAndPrepare() (*qmasque.Client, *uritemplate.Template, bool, error) {
	h.s.Mu.Lock()
	defer h.s.Mu.Unlock()
	if !session.AdvanceHop(&h.s.CoreSession) {
		return nil, nil, false, nil
	}
	if resetErr := h.s.resetHopTemplates(); resetErr != nil {
		return nil, nil, true, resetErr
	}
	if h.s.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
		if h.s.UDPClient == nil {
			h.s.UDPClient = h.NewQUICClient()
		}
	}
	return h.s.UDPClient, h.s.TemplateUDP, true, nil
}

func (h connectUDPPlaneHost) WrapDatagramSplit(pc net.PacketConn, writeMax int, httpLayer string) net.PacketConn {
	// H2 PacketConn splits RFC9297 capsules in WriteTo; DatagramSplitConn is redundant overhead on bulk upload.
	if httpLayer == option.MasqueHTTPLayerH2 {
		return pc
	}
	return split.NewDatagramSplitConn(pc, split.DatagramSplitOptions{
		MaxPayload: writeMax,
		HTTPLayer:  httpLayer,
		MapICMP: func(addr net.Addr, err error) error {
			return split.NewPortUnreachableError(addr)
		},
		MapDataplaneErr: func(op string, err error) error {
			if err == nil || httpLayer != option.MasqueHTTPLayerH3 {
				return err
			}
			return fmt.Errorf("masque h3 dataplane connect-udp %s: %w", op, err)
		},
	})
}

func (h connectUDPPlaneHost) NewQUICClient() *qmasque.Client {
	return cudpclient.NewQUICClient(cudpclient.QUICClientConfig{
		TLSClientConfig: masqueClientTLSConfig(h.s.Options),
		QUICConfig: session.ApplyQUICExperimentalOptions(
			masqueQUICConfigForDial(h.s.Options),
			h.s.Options.QUICExperimental,
		),
		QUICDial:       h.s.quicDialWithPolicy("client_connect_udp"),
		BearerToken:    strings.TrimSpace(h.s.Options.ServerToken),
		LegacyH3Extras: h.s.Options.WarpMasqueLegacyH3Extras,
	})
}

func (s *coreSession) dialUDPAddr(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
	host := connectUDPPlaneHost{s: s}
	return cudpclient.DialAddr(ctx, host, host.ObservabilityInput(template, target), client, template, target)
}

func (s *coreSession) listenPacketConnectUDP(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return s.connectUDPPlane().ListenPacket(ctx, destination)
}

func (s *coreSession) newUDPClient() *qmasque.Client {
	return connectUDPPlaneHost{s: s}.NewQUICClient()
}

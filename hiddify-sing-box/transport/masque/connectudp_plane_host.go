package masque

// connectUDPPlaneHost implements connectudp/client.SessionUDP for coreSession (W-UDP-4 STRUCT-14).
// Lives in package masque (not connectudp/client) to avoid import cycle with coreSession.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	qmasque "github.com/quic-go/masque-go"
	"github.com/sagernet/sing-box/option"
	cudpclient "github.com/sagernet/sing-box/transport/masque/connectudp/client"
	"github.com/sagernet/sing-box/transport/masque/connectudp/split"
	"github.com/sagernet/sing-box/transport/masque/session"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

type connectUDPPlaneHost struct {
	s *coreSession
}

func (s *coreSession) connectUDPPlane() *cudpclient.Plane {
	s.udpPlaneOnce.Do(func() {
		s.udpPlane = cudpclient.NewPlane(connectUDPPlaneHost{s: s})
	})
	return s.udpPlane
}

func (s *coreSession) udpPlaneHost() connectUDPPlaneHost {
	return connectUDPPlaneHost{s: s}
}

// CloseUDPClient tears down the CONNECT-UDP QUIC client (W-IP-6 IP-STRUCT-24 per-plane Close).
func (h connectUDPPlaneHost) CloseUDPClient() {
	if h.s.UDPClient != nil {
		_ = h.s.UDPClient.Close()
		h.s.UDPClient = nil
	}
}

// ResetH2UDPTransportLockedAssumeMu clears the CONNECT-UDP H2 transport pool. Caller must hold s.Mu.
func (h connectUDPPlaneHost) ResetH2UDPTransportLockedAssumeMu() {
	h.s.resetH2UDPTransportLockedAssumeMu()
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
	if h.s.udpDial != nil {
		return h.s.udpDial(ctx, client, template, target)
	}
	// masque-go DialAddr: single bidi CONNECT-UDP stream (UDP-REF-H3-02). Asymmetric legs remain via dialConnectUDPH3Asymmetric for localize.
	return cudpclient.DialH3Production(ctx, nil, client, template, target)
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
	conn, _, err := cudpclient.DialUDPResilient(ctx, host, client, template, target)
	return conn, err
}

func (s *coreSession) listenPacketConnectUDP(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return s.connectUDPPlane().ListenPacket(ctx, destination)
}

func (s *coreSession) newUDPClient() *qmasque.Client {
	return connectUDPPlaneHost{s: s}.NewQUICClient()
}

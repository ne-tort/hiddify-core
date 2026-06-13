package masque

import (
	"context"
	"net"
	"strings"

	qmasque "github.com/quic-go/masque-go"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	"github.com/sagernet/sing-box/transport/masque/session"
	"github.com/yosida95/uritemplate/v3"
)

type connectUDPDialHost struct {
	s *coreSession
}

func (s *coreSession) connectUDPDialHost() connectUDPDialHost {
	return connectUDPDialHost{s: s}
}

func (h connectUDPDialHost) Tag() string {
	return connectudp.TrimTag(h.s.Options.Tag)
}

func (h connectUDPDialHost) CurrentHTTPLayer() string {
	return h.s.currentUDPHTTPLayer()
}

func (h connectUDPDialHost) DialOverHTTP2(ctx context.Context, template *uritemplate.Template, target string) (net.PacketConn, error) {
	return h.s.dialUDPOverHTTP2(ctx, template, target)
}

func (h connectUDPDialHost) DialH3(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
	return connectudp.DialH3Production(ctx, h.s.udpDial, client, template, target)
}

func (h connectUDPDialHost) RecordHTTPLayerSuccess(layer string) {
	h.s.maybeRecordHTTPLayerCacheSuccess(layer)
}

func (h connectUDPDialHost) ResetHTTPFallbackBudgetAfterSuccess() {
	h.s.resetHTTPFallbackBudgetAfterSuccess()
}

func (h connectUDPDialHost) ErrTemplateNotConfigured() error {
	return session.ErrConnectUDPTemplateNotConfigured
}

func (h connectUDPDialHost) observabilityInput(template *uritemplate.Template, target string) connectudp.ObservabilityInput {
	opts := h.s.Options
	return connectudp.ObservabilityInput{
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

func (s *coreSession) dialUDPAddr(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
	host := s.connectUDPDialHost()
	return connectudp.DialAddr(ctx, host, host.observabilityInput(template, target), client, template, target)
}

func (s *coreSession) newUDPClient() *qmasque.Client {
	return connectudp.NewQUICClient(connectudp.QUICClientConfig{
		TLSClientConfig: masqueClientTLSConfig(s.Options),
		QUICConfig: session.ApplyQUICExperimentalOptions(
			masqueQUICConfigForDial(s.Options),
			s.Options.QUICExperimental,
		),
		QUICDial:       s.quicDialWithPolicy("client_connect_udp"),
		BearerToken:    strings.TrimSpace(s.Options.ServerToken),
		LegacyH3Extras: s.Options.WarpMasqueLegacyH3Extras,
	})
}

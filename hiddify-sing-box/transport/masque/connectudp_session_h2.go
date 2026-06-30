package masque

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"sync"

	cudph2 "github.com/sagernet/sing-box/transport/masque/connectudp/h2"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/sagernet/sing-box/transport/masque/session"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

func (s *coreSession) newMasqueClientH2Transport() (*http2.Transport, error) {
	dialOverrideHost := strings.TrimSpace(masqueQuicDialCandidateHost(s.Options))
	alternateDialHost := ""
	if strings.EqualFold(strings.TrimSpace(s.Options.WarpConnectIPProtocol), "cf-connect-ip") {
		alternateDialHost = cudph2.WarpH2AlternateDialHost(dialOverrideHost)
	}
	return h2c.NewClientTransport(h2c.ClientDialConfig{
		TLSConfig:          masqueClientH2TLSConfig(s.Options),
		DialHostCandidates: cudph2.H2DialHostCandidates(strings.TrimSpace(s.Options.WarpConnectIPProtocol), dialOverrideHost, alternateDialHost),
		TCPDial:            s.Options.TCPDial,
		MasqueTCPDialTLS:   s.Options.MasqueTCPDialTLS,
	})
}

func masqueClientH2TLSConfig(opts ClientOptions) *tls.Config {
	return h2c.ClientTLSConfig(masqueClientTLSConfig(opts), resolveTLSServerName(opts))
}

func (s *coreSession) ensureH2TransportCached(ctx context.Context, mu *sync.Mutex, slot **http2.Transport) (*http2.Transport, error) {
	return h2c.EnsureTransportCached(ctx, mu, slot, s.Options.TCPDial != nil, func() (*http2.Transport, error) {
		return s.newMasqueClientH2Transport()
	})
}

func (s *coreSession) ensureH2UDPTransport(ctx context.Context) (*http2.Transport, error) {
	return s.ensureH2TransportCached(ctx, &s.H2UDPMu, &s.H2UDPTransport)
}

func (s *coreSession) ensureH2ConnectStreamTransport(ctx context.Context) (*http2.Transport, error) {
	return s.ensureH2TransportCached(ctx, &s.H2ConnectStreamMu, &s.H2ConnectStreamTransport)
}

func (s *coreSession) closeAllH2ClientTransports() {
	h2c.ResetTransportSlot(&s.H2UDPMu, &s.H2UDPTransport)
	h2c.ResetTransportSlot(&s.H2ConnectStreamMu, &s.H2ConnectStreamTransport)
}

func (s *coreSession) resetH2UDPTransportLockedAssumeMu() {
	h2c.ResetTransportSlot(&s.H2UDPMu, &s.H2UDPTransport)
}

func (s *coreSession) resetH2ConnectStreamTransportLockedAssumeMu() {
	h2c.ResetTransportSlot(&s.H2ConnectStreamMu, &s.H2ConnectStreamTransport)
}

func (s *coreSession) h2OverlayDialConfig() cudph2.H2OverlayDialConfig {
	portNum := int(s.Options.ServerPort)
	if portNum <= 0 {
		portNum = 443
	}
	opts := s.Options
	host := masqueQuicDialCandidateHost(opts)
	return cudph2.H2OverlayDialConfig{
		EnsureTransport: func(ctx context.Context) (*http2.Transport, error) {
			return s.ensureH2UDPTransport(ctx)
		},
		NewTransport: func() (*http2.Transport, error) {
			return s.newMasqueClientH2Transport()
		},
		SetAuthHeader: func(h http.Header) {
			setMasqueAuthorizationHeader(h, opts)
		},
		Tag:                   opts.Tag,
		WarpConnectIPProtocol: opts.WarpConnectIPProtocol,
		QUICDialCandidateHost: host,
		ResolveDialAddr: func() string {
			return masqueDialTarget(host, portNum)
		},
		ErrTemplateNotConfigured: session.ErrConnectUDPTemplateNotConfigured,
	}
}

func (s *coreSession) dialUDPOverHTTP2(ctx context.Context, template *uritemplate.Template, target string) (net.PacketConn, error) {
	if s.h2UDPConnectHook != nil {
		return s.h2UDPConnectHook(ctx, template, target)
	}
	return cudph2.DialH2Overlay(ctx, s.h2OverlayDialConfig(), template, target)
}

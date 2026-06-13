package masque

import (
	"github.com/sagernet/sing-box/transport/masque/session"
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	cudp "github.com/sagernet/sing-box/transport/masque/connectudp"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

type (
	h2ConnectUDPPacketConn = cudp.H2PacketConn
	h2UDPDownlinkItem      = cudp.H2DownlinkItem
	masqueUDPAddr          = cudp.UDPAddr
)

// CapsuleProtocolHeaderValueH2 returns the Capsule-Protocol structured field for Extended CONNECT over HTTP/2.
func CapsuleProtocolHeaderValueH2() string {
	return h2c.CapsuleProtocolHeaderValue()
}

func masqueClientH2TLSConfig(opts ClientOptions) *tls.Config {
	return h2c.ClientTLSConfig(masqueClientTLSConfig(opts), resolveTLSServerName(opts))
}

func (s *coreSession) newMasqueClientH2Transport() (*http2.Transport, error) {
	dialOverrideHost := strings.TrimSpace(masqueQuicDialCandidateHost(s.Options))
	alternateDialHost := ""
	if strings.EqualFold(strings.TrimSpace(s.Options.WarpConnectIPProtocol), "cf-connect-ip") {
		alternateDialHost = cudp.WarpH2AlternateDialHost(dialOverrideHost)
	}
	debug := strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1"
	return h2c.NewClientTransport(h2c.ClientDialConfig{
		TLSConfig:          masqueClientH2TLSConfig(s.Options),
		DialHostCandidates: cudp.H2DialHostCandidates(strings.TrimSpace(s.Options.WarpConnectIPProtocol), dialOverrideHost, alternateDialHost),
		TCPDial:            s.Options.TCPDial,
		MasqueTCPDialTLS:   s.Options.MasqueTCPDialTLS,
		DebugTCPDial: func(network, dialAddr, candidate string) {
			if debug {
				log.Printf("masque h2 tcp dial attempt network=%s addr=%s candidate=%q", network, dialAddr, candidate)
			}
		},
	})
}

func (s *coreSession) ensureH2TransportCached(ctx context.Context, mu *sync.Mutex, slot **http2.Transport) (*http2.Transport, error) {
	return h2c.EnsureTransportCached(ctx, mu, slot, s.Options.TCPDial != nil, func() (*http2.Transport, error) {
		return s.newMasqueClientH2Transport()
	})
}

func (s *coreSession) ensureH2UDPTransport(ctx context.Context) (*http2.Transport, error) {
	return s.ensureH2TransportCached(ctx, &s.H2UDPMu, &s.H2UDPTransport)
}

// ensureH2ConnectStreamTransport uses a dedicated HTTP/2 client pool from CONNECT-UDP/IP so a
// saturated CONNECT-stream iperf run does not exhaust connection-level flow control before the
// post-TCP UDP probe (bench §15.3a).
func (s *coreSession) ensureH2ConnectStreamTransport(ctx context.Context) (*http2.Transport, error) {
	return s.ensureH2TransportCached(ctx, &s.H2ConnectStreamMu, &s.H2ConnectStreamTransport)
}

func closeH2MasqueClientTransport(tr *http2.Transport) {
	h2c.CloseClientTransport(tr)
}

func (s *coreSession) closeAllH2ClientTransports() {
	h2c.ResetTransportSlot(&s.H2UDPMu, &s.H2UDPTransport)
	h2c.ResetTransportSlot(&s.H2ConnectStreamMu, &s.H2ConnectStreamTransport)
}

func warpMasqueH2AlternateDialHost(host string) string {
	return cudp.WarpH2AlternateDialHost(host)
}

func isMasqueH2ExtendedConnectUnsupportedByPeer(err error) bool {
	return cudp.IsH2ExtendedConnectUnsupportedByPeer(err)
}

// resetH2UDPTransportLockedAssumeMu closes the CONNECT-UDP/IP HTTP/2 pool. Caller must hold s.Mu.
func (s *coreSession) resetH2UDPTransportLockedAssumeMu() {
	h2c.ResetTransportSlot(&s.H2UDPMu, &s.H2UDPTransport)
}

// resetH2ConnectStreamTransportLockedAssumeMu closes the CONNECT-stream HTTP/2 pool. Caller must hold s.Mu.
func (s *coreSession) resetH2ConnectStreamTransportLockedAssumeMu() {
	h2c.ResetTransportSlot(&s.H2ConnectStreamMu, &s.H2ConnectStreamTransport)
}

func (s *coreSession) dialUDPOverHTTP2(ctx context.Context, template *uritemplate.Template, target string) (net.PacketConn, error) {
	portNum := int(s.Options.ServerPort)
	if portNum <= 0 {
		portNum = 443
	}
	opts := s.Options
	return cudp.DialH2Overlay(ctx, cudp.H2OverlayDialConfig{
		Hook: s.h2UDPConnectHook,
		EnsureTransport: func(ctx context.Context) (*http2.Transport, error) {
			return s.ensureH2UDPTransport(ctx)
		},
		SetAuthHeader: func(h http.Header) {
			setMasqueAuthorizationHeader(h, opts)
		},
		Tag:                   opts.Tag,
		WarpConnectIPProtocol: opts.WarpConnectIPProtocol,
		QUICDialCandidateHost: masqueQuicDialCandidateHost(opts),
		ResolveDialAddr: func() string {
			return masqueDialTarget(masqueQuicDialCandidateHost(opts), portNum)
		},
		ErrTemplateNotConfigured: session.ErrConnectUDPTemplateNotConfigured,
	}, template, target)
}

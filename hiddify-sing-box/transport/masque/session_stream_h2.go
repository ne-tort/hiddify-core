package masque

import (
	"context"
	"net"
	"net/http"
	"net/url"

	"github.com/sagernet/sing-box/transport/masque/httpx"
	strmclient "github.com/sagernet/sing-box/transport/masque/stream/client"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
)

// h2ConnectRequestContextFactory is swappable in transport tests (request relay leak guard).
var h2ConnectRequestContextFactory = httpx.NewH2ExtendedConnectRequestContext

func (s *coreSession) streamH2Host() strmclient.SessionH2Host {
	if strm.ConnectStreamH2NewTransportPerDial() {
		return strmclient.SessionH2Host{
			EnsureTransport: func(ctx context.Context) (http.RoundTripper, error) {
				return s.newMasqueClientH2Transport()
			},
			GetRoundTripper: s.getTCPRoundTripper,
			ResetTransport:  func() {},
		}
	}
	return strmclient.SessionH2Host{
		EnsureTransport: func(ctx context.Context) (http.RoundTripper, error) {
			return s.ensureH2ConnectStreamTransport(ctx)
		},
		GetRoundTripper: s.getTCPRoundTripper,
		ResetTransport:  s.resetTCPHTTPTransport,
	}
}

func (s *coreSession) streamH2Hooks(options ClientOptions) strmclient.H2Hooks {
	return strmclient.NewH2Hooks(strmclient.H2Wire{
		NewRequestContext: h2ConnectRequestContextFactory,
		RequestURL:        MasqueTCPConnectStreamRequestURL,
		SetAuth: func(h http.Header) {
			setMasqueAuthorizationHeader(h, options)
		},
	})
}

func (s *coreSession) dialTCPStreamH2(ctx context.Context, tcpURL *url.URL, options ClientOptions, targetHost string, destination M.Socksaddr) (net.Conn, error) {
	return strmclient.DialHTTP2(ctx, s.streamH2Hooks(options), s.streamH2Host(), tcpURL, strmclient.H2DialInput{
		Tag:        options.Tag,
		TCPURLHost: tcpURL.Host,
		Server:     options.Server,
		ServerPort: options.ServerPort,
		ResolveDialAddr: func(port int) string {
			return masqueDialTarget(masqueQuicDialCandidateHost(options), port)
		},
		TargetHost: targetHost,
		TargetPort: uint16(destination.Port),
	})
}

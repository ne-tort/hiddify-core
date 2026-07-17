package masque

import (
	"context"
	"net"
	"net/http"
	"net/url"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/pathbuild"
	strmclient "github.com/sagernet/sing-box/transport/masque/stream/client"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

func (s *coreSession) streamH3Host() strmclient.SessionH3Host {
	return strmclient.SessionH3Host{
		GetRoundTripper: s.streamH3RoundTripper,
		ResetHTTP3: func() *http3.Transport {
			s.resetTCPHTTPTransport()
			s.Mu.Lock()
			defer s.Mu.Unlock()
			return s.TCPHTTP
		},
	}
}

func (s *coreSession) streamH3Hooks(options ClientOptions) strmclient.H3Hooks {
	return strmclient.NewH3Hooks(strmclient.H3Wire{
		NewRequestContext: h2ConnectRequestContextFactory,
		RequestURL:        MasqueTCPConnectStreamRequestURL,
		SetAuth: func(h http.Header) {
			setMasqueAuthorizationHeader(h, options)
		},
	})
}

func (s *coreSession) dialTCPStreamHTTP3(ctx context.Context, tcpURL *url.URL, options ClientOptions, targetHost string, targetPort uint16, tcpHTTP *http3.Transport) (net.Conn, error) {
	return strmclient.DialHTTP3(ctx, s.streamH3Hooks(options), s.streamH3Host(), tcpURL, strmclient.H3DialInput{
		Tag:        options.Tag,
		TCPURLHost: tcpURL.Host,
		Server:     options.Server,
		ServerPort: options.ServerPort,
		ResolveDialAddr: func(port int) string {
			return masqueDialTarget(masqueQuicDialCandidateHost(options), port)
		},
		TargetHost: targetHost,
		TargetPort: targetPort,
	}, tcpHTTP)
}

func (s *coreSession) dialTCPStreamOnce(ctx context.Context, templateTCP *uritemplate.Template, options ClientOptions, destination M.Socksaddr, httpLayer string, tcpHTTP *http3.Transport, targetHost string, targetPort uint16) (net.Conn, *url.URL, error) {
	hooks := strmclient.NewOnceHooks(strmclient.OnceDialFuncs{
		DialH2: func(ctx context.Context, tcpURL *url.URL, th string, dest M.Socksaddr) (net.Conn, error) {
			return s.dialTCPStreamH2(ctx, tcpURL, options, th, dest)
		},
		DialH3: func(ctx context.Context, tcpURL *url.URL, th string, tp uint16, h3t *http3.Transport) (net.Conn, error) {
			return s.dialTCPStreamHTTP3(ctx, tcpURL, options, th, tp, h3t)
		},
	})
	return strmclient.DialOnce(ctx, hooks, strmclient.OnceInput{
		Template:           templateTCP,
		Destination:        destination,
		HTTPLayer:          httpLayer,
		HTTPLayerH2:        option.MasqueHTTPLayerH2,
		TCPHTTP:            tcpHTTP,
		TargetHost:         targetHost,
		TargetPort:         targetPort,
		PathObfuscationKey: pathbuild.ActiveKey(options.PathObfuscation),
	})
}

// streamH3RoundTripper returns defaultTransport for ephemeral RoundTrippers;
// shared TCPHTTP pool dials use the session TCPRoundTripper hook when set.
func (s *coreSession) streamH3RoundTripper(defaultTransport http.RoundTripper) http.RoundTripper {
	if defaultTransport != nil && defaultTransport != s.TCPHTTP {
		return defaultTransport
	}
	return s.getTCPRoundTripper(defaultTransport)
}

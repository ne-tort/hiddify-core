package masque

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/h3"
	"github.com/sagernet/sing-box/transport/masque/httpx"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

var streamDialOnceHooks = strm.DialOnceHooks{
	PathHostForTemplate: MasqueTCPPathHostForTemplate,
	FixExpandedURL:      FixMasqueExpandedTCPConnectStreamURL,
	RewritePercentIPv6:  RewriteMasqueTCPURLIfPercentEncodedIPv6,
}

type tcpStreamDialH3Host struct {
	s *coreSession
}

func (h tcpStreamDialH3Host) RoundTripper(defaultTransport http.RoundTripper) http.RoundTripper {
	return h.s.getTCPRoundTripper(defaultTransport)
}

func (h tcpStreamDialH3Host) ResetHTTP3Transport() *http3.Transport {
	h.s.resetTCPHTTPTransport()
	h.s.Mu.Lock()
	defer h.s.Mu.Unlock()
	return h.s.TCPHTTP
}

func streamDialH3Hooks(options ClientOptions) strm.DialH3Hooks {
	return strm.DialH3Hooks{
		NewRequestContext: httpx.NewH2ExtendedConnectRequestContext,
		BuildRequest: func(ctx context.Context, url, serverHost string, usePipe bool) (*http.Request, *io.PipeReader, io.WriteCloser, error) {
			return h3.ConnectRequest(ctx, url, serverHost, usePipe, func(h http.Header) {
				setMasqueAuthorizationHeader(h, options)
			})
		},
		TunnelFromResponse: func(ctx context.Context, resp *http.Response, upload io.WriteCloser, targetHost string, targetPort uint16) (net.Conn, error) {
			allowPipe := h3.ConnectUsePipeUpload()
			return strm.H3TunnelFromResponse(ctx, resp, upload, targetHost, targetPort, allowPipe, h3.ConnectTunnelFromResponse)
		},
		UsePipeUpload: h3.ConnectUsePipeUpload,
		RequestURL:    MasqueTCPConnectStreamRequestURL,
		ClassifyError: func(err error) string { return string(ClassifyError(err)) },
		AuthFailed:    ErrAuthFailed,
	}
}

func (s *coreSession) dialTCPStreamHTTP3(ctx context.Context, tcpURL *url.URL, options ClientOptions, targetHost string, targetPort uint16, tcpHTTP *http3.Transport) (net.Conn, error) {
	portNum := int(options.ServerPort)
	if portNum <= 0 {
		portNum = 443
	}
	return strm.DialHTTP3ConnectStream(ctx, streamDialH3Hooks(options), tcpStreamDialH3Host{s: s}, tcpURL, strm.DialH3LogInput{
		Tag:        options.Tag,
		TCPURLHost: tcpURL.Host,
		Server:     options.Server,
		ServerPort: options.ServerPort,
		ResolveDialAddr: func(port int) string {
			return masqueDialTarget(masqueQuicDialCandidateHost(options), port)
		},
	}, targetHost, targetPort, tcpHTTP)
}

func (s *coreSession) dialTCPStreamOnce(ctx context.Context, templateTCP *uritemplate.Template, options ClientOptions, destination M.Socksaddr, httpLayer string, tcpHTTP *http3.Transport, targetHost string, targetPort uint16, pathBracket bool) (net.Conn, *url.URL, error) {
	hooks := streamDialOnceHooks
	hooks.DialH2 = func(ctx context.Context, tcpURL *url.URL, targetHost string, destination M.Socksaddr) (net.Conn, error) {
		return s.dialTCPStreamH2(ctx, tcpURL, options, targetHost, destination)
	}
	hooks.DialH3 = func(ctx context.Context, tcpURL *url.URL, targetHost string, targetPort uint16, tcpHTTP *http3.Transport) (net.Conn, error) {
		return s.dialTCPStreamHTTP3(ctx, tcpURL, options, targetHost, targetPort, tcpHTTP)
	}
	return strm.DialOnce(ctx, hooks, templateTCP, destination, httpLayer, option.MasqueHTTPLayerH2, tcpHTTP, targetHost, targetPort, pathBracket)
}

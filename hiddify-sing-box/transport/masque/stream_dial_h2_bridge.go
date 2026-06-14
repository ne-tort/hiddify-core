package masque

import (
	"github.com/sagernet/sing-box/transport/masque/session"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/sagernet/sing-box/transport/masque/httpx"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
)

var h2ConnectRequestContextFactory = httpx.NewH2ExtendedConnectRequestContext

type tcpStreamDialH2Host struct {
	s *coreSession
}

func (h tcpStreamDialH2Host) EnsureH2ConnectStreamTransport(ctx context.Context) (http.RoundTripper, error) {
	return h.s.ensureH2ConnectStreamTransport(ctx)
}

func (h tcpStreamDialH2Host) RoundTripper(defaultTransport http.RoundTripper) http.RoundTripper {
	return h.s.getTCPRoundTripper(defaultTransport)
}

func (h tcpStreamDialH2Host) ResetH2ConnectStreamTransport() {
	h.s.resetTCPHTTPTransport()
}

func streamDialH2Hooks(options ClientOptions) strm.DialH2Hooks {
	return strm.DialH2Hooks{
		NewRequestContext: h2ConnectRequestContextFactory,
		NewConnectUploadBody: func(pr *io.PipeReader) io.Reader {
			return &h2c.ExtendedConnectUploadBody{Pipe: pr}
		},
		SetAuthHeader: func(h http.Header) {
			setMasqueAuthorizationHeader(h, options)
		},
		RequestURL: MasqueTCPConnectStreamRequestURL,
		TunnelFromResponse: func(ctx context.Context, resp *http.Response, upload *io.PipeWriter, uploadBody io.Reader, targetHost string, targetPort uint16) (net.Conn, error) {
			return h2c.ConnectTunnelFromResponse(ctx, resp, upload, uploadBody, targetHost, targetPort)
		},
		ClassifyError: func(err error) string { return string(session.ClassifyError(err)) },
		AuthFailed:    session.ErrAuthFailed,
	}
}

func (s *coreSession) dialTCPStreamH2(ctx context.Context, tcpURL *url.URL, options ClientOptions, targetHost string, destination M.Socksaddr) (net.Conn, error) {
	portNum := int(options.ServerPort)
	if portNum <= 0 {
		portNum = 443
	}
	return strm.DialHTTP2ConnectStream(ctx, streamDialH2Hooks(options), tcpStreamDialH2Host{s: s}, tcpURL, strm.DialH2LogInput{
		Tag:        options.Tag,
		TCPURLHost: tcpURL.Host,
		Server:     options.Server,
		ServerPort: options.ServerPort,
		ResolveDialAddr: func(port int) string {
			return masqueDialTarget(masqueQuicDialCandidateHost(options), port)
		},
	}, targetHost, uint16(destination.Port))
}

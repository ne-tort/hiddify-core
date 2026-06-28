package client

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque/h3"
	"github.com/sagernet/sing-box/transport/masque/httpx"
	"github.com/sagernet/sing-box/transport/masque/session"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// H3Host is session-owned HTTP/3 CONNECT-stream transport state.
type H3Host = strm.DialH3Host

// H3Hooks is the CONNECT-stream H3 dial hook bundle.
type H3Hooks = strm.DialH3Hooks

// H3Auth sets MASQUE authorization on CONNECT requests.
type H3Auth func(h http.Header)

// H3Wire carries masque-root wire helpers injected at dial time.
type H3Wire struct {
	NewRequestContext func(parent context.Context) (context.Context, func(success bool))
	RequestURL        func(*url.URL) string
	SetAuth           H3Auth
	ClassifyError     func(err error) string
	AuthFailed        error
}

// NewH3Hooks builds production CONNECT-stream H3 dial hooks.
func NewH3Hooks(w H3Wire) strm.DialH3Hooks {
	if w.AuthFailed == nil {
		w.AuthFailed = session.ErrAuthFailed
	}
	if w.ClassifyError == nil {
		w.ClassifyError = func(err error) string { return string(session.ClassifyError(err)) }
	}
	newReqCtx := httpx.NewH2ExtendedConnectRequestContext
	if w.NewRequestContext != nil {
		newReqCtx = w.NewRequestContext
	}
	return strm.DialH3Hooks{
		NewRequestContext: newReqCtx,
		BuildRequest: func(ctx context.Context, url, serverHost string, usePipe bool) (*http.Request, *io.PipeReader, io.WriteCloser, error) {
			return h3.ConnectRequest(ctx, url, serverHost, false, func(h http.Header) {
				if w.SetAuth != nil {
					w.SetAuth(h)
				}
			})
		},
		TunnelFromResponse: func(ctx context.Context, resp *http.Response, upload io.WriteCloser, targetHost string, targetPort uint16) (net.Conn, error) {
			return strm.H3TunnelFromResponse(ctx, resp, upload, targetHost, targetPort, false, h3.ConnectTunnelFromResponse)
		},
		UsePipeUpload: func() bool { return false },
		RequestURL:    w.RequestURL,
		ClassifyError: w.ClassifyError,
		AuthFailed:    w.AuthFailed,
	}
}

// H3DialInput carries one H3 CONNECT-stream dial attempt (logging + target).
type H3DialInput struct {
	Tag             string
	TCPURLHost      string
	Server          string
	ServerPort      uint16
	ResolveDialAddr func(port int) string
	TargetHost      string
	TargetPort      uint16
}

func (in H3DialInput) logInput() strm.DialH3LogInput {
	return strm.DialH3LogInput{
		Tag:             in.Tag,
		TCPURLHost:      in.TCPURLHost,
		Server:          in.Server,
		ServerPort:      in.ServerPort,
		ResolveDialAddr: in.ResolveDialAddr,
	}
}

// DialHTTP3 performs one HTTP/3 CONNECT-stream dial with retry on transport faults.
func DialHTTP3(ctx context.Context, hooks strm.DialH3Hooks, host H3Host, tcpURL *url.URL, in H3DialInput, tcpHTTP *http3.Transport) (net.Conn, error) {
	return strm.DialHTTP3ConnectStream(ctx, hooks, host, tcpURL, in.logInput(), in.TargetHost, in.TargetPort, tcpHTTP)
}

// SessionH3Host implements H3Host via callbacks (wired from package masque on coreSession).
type SessionH3Host struct {
	GetRoundTripper func(defaultTransport http.RoundTripper) http.RoundTripper
	ResetHTTP3      func() *http3.Transport
}

func (h SessionH3Host) RoundTripper(defaultTransport http.RoundTripper) http.RoundTripper {
	if h.GetRoundTripper != nil {
		return h.GetRoundTripper(defaultTransport)
	}
	return defaultTransport
}

func (h SessionH3Host) ResetHTTP3Transport() *http3.Transport {
	if h.ResetHTTP3 != nil {
		return h.ResetHTTP3()
	}
	return nil
}

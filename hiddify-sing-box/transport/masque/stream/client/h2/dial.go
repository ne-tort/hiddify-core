package h2

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/sagernet/sing-box/transport/masque/httpx"
	"github.com/sagernet/sing-box/transport/masque/session"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// Host is session-owned HTTP/2 CONNECT-stream transport state.
type Host = strm.DialH2Host

// Hooks is the CONNECT-stream H2 dial hook bundle.
type Hooks = strm.DialH2Hooks

// Auth sets MASQUE authorization on CONNECT requests.
type Auth func(h http.Header)

// Wire carries masque-root wire helpers injected at dial time.
type Wire struct {
	NewRequestContext func(parent context.Context) (context.Context, func(success bool))
	RequestURL        func(*url.URL) string
	SetAuth           Auth
	ClassifyError     func(err error) string
	AuthFailed        error
}

// NewHooks builds production CONNECT-stream H2 dial hooks (Extended CONNECT + h2 tunnel).
func NewHooks(w Wire) strm.DialH2Hooks {
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
	return strm.DialH2Hooks{
		NewRequestContext:    newReqCtx,
		NewConnectUploadPipe: h2c.NewConnectUploadPipe,
		NewConnectUploadBody: func(uploadR io.Reader) io.Reader {
			return &h2c.ExtendedConnectUploadBody{Pipe: uploadR}
		},
		SetAuthHeader:      w.SetAuth,
		RequestURL:         w.RequestURL,
		TunnelFromResponse: h2c.ConnectTunnelFromResponse,
		ClassifyError:      w.ClassifyError,
		AuthFailed:         w.AuthFailed,
	}
}

// DialInput carries one H2 CONNECT-stream dial attempt (logging + target).
type DialInput struct {
	Tag             string
	TCPURLHost      string
	Server          string
	ServerPort      uint16
	ResolveDialAddr func(port int) string
	TargetHost      string
	TargetPort      uint16
}

func (in DialInput) logInput() strm.DialH2LogInput {
	return strm.DialH2LogInput{
		Tag:             in.Tag,
		TCPURLHost:      in.TCPURLHost,
		Server:          in.Server,
		ServerPort:      in.ServerPort,
		ResolveDialAddr: in.ResolveDialAddr,
	}
}

// DialHTTP2 performs one HTTP/2 Extended CONNECT-stream dial with retry on transport faults.
func DialHTTP2(ctx context.Context, hooks strm.DialH2Hooks, host Host, tcpURL *url.URL, in DialInput) (net.Conn, error) {
	return strm.DialHTTP2ConnectStream(ctx, hooks, host, tcpURL, in.logInput(), in.TargetHost, in.TargetPort)
}

// SessionHost implements Host via callbacks (wired from package masque on coreSession).
type SessionHost struct {
	EnsureTransport func(ctx context.Context) (http.RoundTripper, error)
	GetRoundTripper func(defaultTransport http.RoundTripper) http.RoundTripper
	ResetTransport  func()
}

func (h SessionHost) EnsureH2ConnectStreamTransport(ctx context.Context) (http.RoundTripper, error) {
	return h.EnsureTransport(ctx)
}

func (h SessionHost) RoundTripper(defaultTransport http.RoundTripper) http.RoundTripper {
	if h.GetRoundTripper != nil {
		return h.GetRoundTripper(defaultTransport)
	}
	return defaultTransport
}

func (h SessionHost) ResetH2ConnectStreamTransport() {
	if h.ResetTransport != nil {
		h.ResetTransport()
	}
}

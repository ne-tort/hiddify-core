package client

import (
	"context"
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
		BuildRequest: func(ctx context.Context, url, serverHost string) (*http.Request, error) {
			req, err := h3.ConnectRequest(ctx, url, serverHost, func(h http.Header) {
				if w.SetAuth != nil {
					w.SetAuth(h)
				}
			})
			if err != nil {
				return nil, err
			}
			if leg := strm.ConnectStreamLegFromContext(ctx); leg != "" {
				req.Header.Set(strm.ConnectStreamLegHeader, leg)
			}
			if pairID := strm.ConnectStreamPairFromContext(ctx); pairID != "" {
				req.Header.Set(strm.ConnectStreamPairHeader, pairID)
			}
			return req, nil
		},
		TunnelFromResponse: func(ctx context.Context, resp *http.Response, targetHost string, targetPort uint16) (net.Conn, error) {
			return strm.H3TunnelFromResponse(ctx, resp, targetHost, targetPort, h3.ConnectTunnelFromResponse)
		},
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

// DialHTTP3 performs HTTP/3 CONNECT-stream dial (single bidi by default; P2 dual when env=1).
func DialHTTP3(ctx context.Context, hooks strm.DialH3Hooks, host H3Host, tcpURL *url.URL, in H3DialInput, tcpHTTP *http3.Transport) (net.Conn, error) {
	logIn := in.logInput()
	if strm.ConnectStreamUseDualConnect() {
		return dialHTTP3DualConnect(ctx, hooks, host, tcpURL, logIn, in.TargetHost, in.TargetPort, tcpHTTP)
	}
	return strm.DialHTTP3ConnectStream(ctx, hooks, host, tcpURL, logIn, in.TargetHost, in.TargetPort, tcpHTTP)
}

func dialHTTP3DualConnect(
	ctx context.Context,
	hooks strm.DialH3Hooks,
	host H3Host,
	tcpURL *url.URL,
	logIn strm.DialH3LogInput,
	targetHost string,
	targetPort uint16,
	tcpHTTP *http3.Transport,
) (net.Conn, error) {
	pairCtx := strm.ContextWithConnectStreamPair(ctx, strm.NewConnectStreamPairID())
	dlConn, err := strm.DialHTTP3ConnectStreamLeg(pairCtx, hooks, host, tcpURL, logIn, targetHost, targetPort, tcpHTTP, strm.ConnectStreamLegDownload)
	if err != nil {
		return nil, err
	}
	ulConn, err := strm.DialHTTP3ConnectStreamLeg(pairCtx, hooks, host, tcpURL, logIn, targetHost, targetPort, tcpHTTP, strm.ConnectStreamLegUpload)
	if err != nil {
		_ = dlConn.Close()
		return nil, err
	}
	remote := dlConn.RemoteAddr()
	if remote == nil {
		remote = ulConn.RemoteAddr()
	}
	inner := h3.NewDualTunnelConn(h3.DualTunnelConnParams{
		Download: dlConn,
		Upload:   ulConn,
		Ctx:      context.WithoutCancel(ctx),
		Local:    dlConn.LocalAddr(),
		Remote:   remote,
	})
	if inner == nil {
		_ = dlConn.Close()
		_ = ulConn.Close()
		return nil, strm.Errs.TCPConnectStreamFailed
	}
	return strm.NewTunnelConn(inner), nil
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

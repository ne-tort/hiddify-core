package stream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	strmconn "github.com/sagernet/sing-box/transport/masque/stream/conn"
)

// H2ConnectStreamProto is the :protocol value for Extended CONNECT TCP (draft-ietf-httpbis-connect-tcp).
const H2ConnectStreamProto = "connect-tcp"

// DialH2LogInput carries CONNECT-stream H2 attempt logging fields (no secrets).
type DialH2LogInput struct {
	Tag             string
	TCPURLHost      string
	Server          string
	ServerPort      uint16
	ResolveDialAddr func(port int) string
}

// DialH2Host wires session-owned HTTP/2 CONNECT-stream transport state.
type DialH2Host interface {
	EnsureH2ConnectStreamTransport(ctx context.Context) (http.RoundTripper, error)
	RoundTripper(defaultTransport http.RoundTripper) http.RoundTripper
	ResetH2ConnectStreamTransport()
}

// DialH2Hooks supplies masque-layer CONNECT-stream H2 dependencies (wired from transport/masque).
type DialH2Hooks struct {
	NewRequestContext    func(parent context.Context) (ctx context.Context, stop func(success bool))
	NewConnectUploadPipe func() (uploadR io.ReadCloser, uploadW io.WriteCloser)
	NewConnectUploadBody func(uploadR io.Reader) io.Reader
	SetAuthHeader        func(h http.Header)
	RequestURL           func(u *url.URL) string
	TunnelFromResponse   func(ctx context.Context, resp *http.Response, upload io.WriteCloser, uploadBody io.Reader, targetHost string, targetPort uint16) (net.Conn, error)
	ClassifyError        func(err error) string
	AuthFailed           error
}

// DialHTTP2ConnectStream performs one HTTP/2 Extended CONNECT-stream dial with retry on transport faults.
func DialHTTP2ConnectStream(
	ctx context.Context,
	hooks DialH2Hooks,
	host DialH2Host,
	tcpURL *url.URL,
	logIn DialH2LogInput,
	targetHost string,
	targetPort uint16,
) (net.Conn, error) {
	serverHost := tcpURL.Host
	if serverHost == "" {
		serverHost = net.JoinHostPort(logIn.Server, strconv.Itoa(int(logIn.ServerPort)))
	}
	tcpLogHost := tcpURL.Host
	if tcpLogHost == "" {
		tcpLogHost = serverHost
	}
	portNum := int(logIn.ServerPort)
	if portNum <= 0 {
		portNum = 443
	}
	var dialAddr string
	if logIn.ResolveDialAddr != nil {
		dialAddr = logIn.ResolveDialAddr(portNum)
	}
	select {
	case <-ctx.Done():
		return nil, errors.Join(Errs.TCPConnectStreamFailed, context.Cause(ctx))
	default:
	}
	log.Printf("masque_http_layer_attempt layer=h2 tag=%s tcp_stream=1 target=%s dial=%s",
		strings.TrimSpace(logIn.Tag), tcpLogHost, dialAddr)

	maxAttempts := ConnectStreamDialMaxAttempts()
	var lastRoundTripErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctxErr := context.Cause(ctx); ctxErr != nil {
			return nil, errors.Join(Errs.TCPConnectStreamFailed, ctxErr)
		}
		tr, err := host.EnsureH2ConnectStreamTransport(ctx)
		if err != nil {
			return nil, errors.Join(Errs.TCPConnectStreamFailed, err)
		}

		if hooks.NewConnectUploadPipe == nil {
			return nil, errors.Join(Errs.TCPConnectStreamFailed, errors.New("masque h2: connect-stream upload pipe hook required"))
		}
		uploadR, uploadW := hooks.NewConnectUploadPipe()
		streamCtx, stopReqCtxRelay := hooks.NewRequestContext(ctx)
		uploadBody := hooks.NewConnectUploadBody(uploadR)
		req, reqErr := http.NewRequestWithContext(streamCtx, http.MethodConnect, hooks.RequestURL(tcpURL), uploadBody)
		if reqErr != nil {
			stopReqCtxRelay(false)
			_ = uploadR.Close()
			_ = uploadW.Close()
			return nil, errors.Join(Errs.TCPConnectStreamFailed, fmt.Errorf("masque h2: tcp connect-stream build request: %w", reqErr))
		}
		req.Host = serverHost
		req.Header = make(http.Header)
		req.Header.Set(":protocol", H2ConnectStreamProto)
		if hooks.SetAuthHeader != nil {
			hooks.SetAuthHeader(req.Header)
		}
		req.ContentLength = -1

		roundTripper := host.RoundTripper(tr)
		resp, roundTripErr := roundTripper.RoundTrip(req)
		if roundTripErr != nil {
			stopReqCtxRelay(false)
			lastRoundTripErr = roundTripErr
			_ = uploadR.Close()
			_ = uploadW.Close()
			if attempt+1 < maxAttempts && connectStreamRoundTripShouldRetry(roundTripErr) {
				host.ResetH2ConnectStreamTransport()
				if backoffErr := waitContextBackoff(ctx, ConnectStreamDialBackoff(attempt)); backoffErr != nil {
					return nil, errors.Join(Errs.TCPConnectStreamFailed, backoffErr)
				}
				continue
			}
			return nil, errors.Join(Errs.TCPConnectStreamFailed, fmt.Errorf("masque h2: tcp connect-stream roundtrip: %w", roundTripErr))
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			stopReqCtxRelay(false)
			_ = uploadR.Close()
			_ = uploadW.Close()
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				return nil, JoinConnectStreamHTTPStatus(hooks.AuthFailed, resp.StatusCode, hooks.RequestURL(tcpURL))
			}
			return nil, fmt.Errorf("masque h2: %w: status=%d url=%s", Errs.TCPConnectStreamFailed, resp.StatusCode, hooks.RequestURL(tcpURL))
		}
		stopReqCtxRelay(true)
		if ctxErr := context.Cause(ctx); ctxErr != nil {
			stopReqCtxRelay(false)
			_ = uploadR.Close()
			_ = uploadW.Close()
			_ = resp.Body.Close()
			return nil, errors.Join(Errs.TCPConnectStreamFailed, ctxErr)
		}
		conn, err := hooks.TunnelFromResponse(streamCtx, resp, uploadW, uploadBody, targetHost, targetPort)
		if err != nil {
			stopReqCtxRelay(false)
			_ = uploadR.Close()
			_ = uploadW.Close()
			_ = resp.Body.Close()
			return nil, errors.Join(err, context.Cause(ctx))
		}
		strmconn.SetStreamCancel(conn, func(error) { stopReqCtxRelay(false) })
		return conn, nil
	}
	if lastRoundTripErr != nil {
		return nil, errors.Join(Errs.TCPConnectStreamFailed, lastRoundTripErr)
	}
	return nil, Errs.TCPConnectStreamFailed
}

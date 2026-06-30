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
)

// H2ConnectStreamProto is the :protocol header value for Extended CONNECT over HTTP/2 (RFC 8441).
const H2ConnectStreamProto = "HTTP/2"

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
		select {
		case <-ctx.Done():
			return nil, errors.Join(Errs.TCPConnectStreamFailed, context.Cause(ctx))
		default:
		}
		tr, err := host.EnsureH2ConnectStreamTransport(ctx)
		if err != nil {
			return nil, errors.Join(Errs.TCPConnectStreamFailed, err)
		}
		TraceTCPf("masque tcp connect_stream h2 host=%s port=%d attempt=%d", targetHost, targetPort, attempt+1)

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
			if errors.Is(roundTripErr, context.Canceled) || errors.Is(roundTripErr, context.DeadlineExceeded) {
				TraceTCPf("masque tcp connect_stream h2 cancelled host=%s port=%d attempt=%d error_class=%s err=%v",
					targetHost, targetPort, attempt+1, hooks.ClassifyError(Errs.TCPConnectStreamFailed), roundTripErr)
				return nil, errors.Join(Errs.TCPConnectStreamFailed, roundTripErr)
			}
			if attempt+1 < maxAttempts && IsRetryableTCPStreamError(roundTripErr) && ctx.Err() == nil {
				TraceTCPf("masque tcp connect_stream h2 retry host=%s port=%d attempt=%d error_class=%s err=%v",
					targetHost, targetPort, attempt+1, hooks.ClassifyError(Errs.TCPConnectStreamFailed), roundTripErr)
				host.ResetH2ConnectStreamTransport()
				if backoffErr := waitContextBackoff(ctx, ConnectStreamDialBackoff(attempt)); backoffErr != nil {
					return nil, errors.Join(Errs.TCPConnectStreamFailed, backoffErr)
				}
				continue
			}
			TraceTCPf("masque tcp connect_stream h2 failed host=%s port=%d status=roundtrip_error error_class=%s err=%v",
				targetHost, targetPort, hooks.ClassifyError(Errs.TCPConnectStreamFailed), roundTripErr)
			if IsRetryableTCPStreamError(roundTripErr) {
				host.ResetH2ConnectStreamTransport()
			}
			return nil, errors.Join(Errs.TCPConnectStreamFailed, fmt.Errorf("masque h2: tcp connect-stream roundtrip: %w", roundTripErr))
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			stopReqCtxRelay(false)
			_ = uploadR.Close()
			_ = uploadW.Close()
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				TraceTCPf("masque tcp connect_stream h2 denied host=%s port=%d status=%d error_class=%s",
					targetHost, targetPort, resp.StatusCode, hooks.ClassifyError(hooks.AuthFailed))
				return nil, errors.Join(hooks.AuthFailed, fmt.Errorf("status=%d url=%s", resp.StatusCode, hooks.RequestURL(tcpURL)))
			}
			TraceTCPf("masque tcp connect_stream h2 failed host=%s port=%d status=%d error_class=%s",
				targetHost, targetPort, resp.StatusCode, hooks.ClassifyError(Errs.TCPConnectStreamFailed))
			return nil, fmt.Errorf("masque h2: %w: status=%d url=%s", Errs.TCPConnectStreamFailed, resp.StatusCode, hooks.RequestURL(tcpURL))
		}
		if ctxErr := context.Cause(ctx); ctxErr != nil {
			stopReqCtxRelay(false)
			_ = uploadR.Close()
			_ = uploadW.Close()
			_ = resp.Body.Close()
			return nil, errors.Join(Errs.TCPConnectStreamFailed, ctxErr)
		}
		stopReqCtxRelay(true)
		TraceTCPf("masque tcp connect_stream h2 success host=%s port=%d status=%d", targetHost, targetPort, resp.StatusCode)
		return hooks.TunnelFromResponse(streamCtx, resp, uploadW, uploadBody, targetHost, targetPort)
	}
	if lastRoundTripErr != nil {
		if IsRetryableTCPStreamError(lastRoundTripErr) {
			host.ResetH2ConnectStreamTransport()
		}
		return nil, errors.Join(Errs.TCPConnectStreamFailed, lastRoundTripErr)
	}
	return nil, Errs.TCPConnectStreamFailed
}

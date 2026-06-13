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
	"time"

	"github.com/quic-go/quic-go/http3"
)

// DialH3LogInput carries CONNECT-stream H3 attempt logging fields (no secrets).
type DialH3LogInput struct {
	Tag             string
	TCPURLHost      string
	Server          string
	ServerPort      uint16
	ResolveDialAddr func(port int) string
}

// DialH3Host wires session-owned HTTP/3 transport state for CONNECT-stream dial.
type DialH3Host interface {
	RoundTripper(defaultTransport http.RoundTripper) http.RoundTripper
	ResetHTTP3Transport() *http3.Transport
}

// DialH3Hooks supplies masque-layer CONNECT-stream H3 dependencies (wired from transport/masque).
type DialH3Hooks struct {
	NewRequestContext func(parent context.Context) (ctx context.Context, stop func(success bool))
	BuildRequest      func(ctx context.Context, url, serverHost string, usePipe bool) (*http.Request, *io.PipeReader, io.WriteCloser, error)
	TunnelFromResponse func(ctx context.Context, resp *http.Response, upload io.WriteCloser, targetHost string, targetPort uint16) (net.Conn, error)
	UsePipeUpload     func() bool
	RequestURL        func(u *url.URL) string
	ClassifyError     func(err error) string
	AuthFailed        error
}

// DialHTTP3ConnectStream performs one HTTP/3 CONNECT-stream dial with retry on transport faults.
func DialHTTP3ConnectStream(
	ctx context.Context,
	hooks DialH3Hooks,
	host DialH3Host,
	tcpURL *url.URL,
	logIn DialH3LogInput,
	targetHost string,
	targetPort uint16,
	tcpHTTP *http3.Transport,
) (net.Conn, error) {
	return DialHTTP3ConnectStreamLeg(ctx, hooks, host, tcpURL, logIn, targetHost, targetPort, tcpHTTP, hooks.UsePipeUpload(), "")
}

// DialHTTP3ConnectStreamLeg dials one CONNECT-stream leg with an explicit pipe/bidi choice (P2 dual dial).
func DialHTTP3ConnectStreamLeg(
	ctx context.Context,
	hooks DialH3Hooks,
	host DialH3Host,
	tcpURL *url.URL,
	logIn DialH3LogInput,
	targetHost string,
	targetPort uint16,
	tcpHTTP *http3.Transport,
	usePipe bool,
	legLabel string,
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
	log.Printf("masque_http_layer_attempt layer=h3 tag=%s tcp_stream=1 target=%s dial=%s%s",
		strings.TrimSpace(logIn.Tag), tcpLogHost, dialAddr, dialH3LegLogSuffix(legLabel))
	maxAttempts := ConnectStreamDialMaxAttempts()
	var lastRoundTripErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctxErr := context.Cause(ctx); ctxErr != nil {
			return nil, errors.Join(Errs.TCPConnectStreamFailed, ctxErr)
		}
		TraceTCPf("masque tcp connect_stream request host=%s port=%d attempt=%d%s", targetHost, targetPort, attempt+1, dialH3LegLogSuffix(legLabel))
		streamCtx, stopReqCtxRelay := hooks.NewRequestContext(ctx)
		req, pr, pw, reqErr := hooks.BuildRequest(streamCtx, hooks.RequestURL(tcpURL), serverHost, usePipe)
		if reqErr != nil {
			stopReqCtxRelay(false)
			return nil, errors.Join(Errs.TCPConnectStreamFailed, reqErr)
		}
		if pr != nil {
			req.Body = pr
		}
		roundTripper := host.RoundTripper(tcpHTTP)
		resp, roundTripErr := roundTripper.RoundTrip(req)
		if roundTripErr != nil {
			stopReqCtxRelay(false)
			lastRoundTripErr = roundTripErr
			if pr != nil {
				_ = pr.Close()
			}
			if pw != nil {
				_ = pw.Close()
			}
			if errors.Is(roundTripErr, context.Canceled) || errors.Is(roundTripErr, context.DeadlineExceeded) {
				TraceTCPf("masque tcp connect_stream cancelled host=%s port=%d attempt=%d error_class=%s err=%v",
					targetHost, targetPort, attempt+1, hooks.ClassifyError(Errs.TCPConnectStreamFailed), roundTripErr)
				return nil, errors.Join(Errs.TCPConnectStreamFailed, roundTripErr)
			}
			if attempt+1 < maxAttempts && IsRetryableTCPStreamError(roundTripErr) && ctx.Err() == nil {
				TraceTCPf("masque tcp connect_stream retry host=%s port=%d attempt=%d error_class=%s err=%v",
					targetHost, targetPort, attempt+1, hooks.ClassifyError(Errs.TCPConnectStreamFailed), roundTripErr)
				tcpHTTP = host.ResetHTTP3Transport()
				if backoffErr := waitContextBackoff(ctx, ConnectStreamDialBackoff(attempt)); backoffErr != nil {
					return nil, errors.Join(Errs.TCPConnectStreamFailed, backoffErr)
				}
				continue
			}
			TraceTCPf("masque tcp connect_stream failed host=%s port=%d status=roundtrip_error error_class=%s err=%v",
				targetHost, targetPort, hooks.ClassifyError(Errs.TCPConnectStreamFailed), roundTripErr)
			if IsRetryableTCPStreamError(roundTripErr) {
				host.ResetHTTP3Transport()
			}
			return nil, errors.Join(Errs.TCPConnectStreamFailed, roundTripErr)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			stopReqCtxRelay(false)
			if pr != nil {
				_ = pr.Close()
			}
			if pw != nil {
				_ = pw.Close()
			}
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				TraceTCPf("masque tcp connect_stream denied host=%s port=%d status=%d error_class=%s",
					targetHost, targetPort, resp.StatusCode, hooks.ClassifyError(hooks.AuthFailed))
				return nil, errors.Join(hooks.AuthFailed, fmt.Errorf("status=%d url=%s", resp.StatusCode, hooks.RequestURL(tcpURL)))
			}
			TraceTCPf("masque tcp connect_stream failed host=%s port=%d status=%d error_class=%s",
				targetHost, targetPort, resp.StatusCode, hooks.ClassifyError(Errs.TCPConnectStreamFailed))
			return nil, fmt.Errorf("%w: status=%d url=%s", Errs.TCPConnectStreamFailed, resp.StatusCode, hooks.RequestURL(tcpURL))
		}
		if ctxErr := context.Cause(ctx); ctxErr != nil {
			stopReqCtxRelay(false)
			if pr != nil {
				_ = pr.Close()
			}
			if pw != nil {
				_ = pw.Close()
			}
			_ = resp.Body.Close()
			return nil, errors.Join(Errs.TCPConnectStreamFailed, ctxErr)
		}
		TraceTCPf("masque tcp connect_stream success host=%s port=%d status=%d pipe_upload=%t%s",
			targetHost, targetPort, resp.StatusCode, usePipe, dialH3LegLogSuffix(legLabel))
		stopReqCtxRelay(true)
		conn, err := hooks.TunnelFromResponse(streamCtx, resp, pw, targetHost, targetPort)
		if err != nil {
			if pw != nil {
				_ = pw.Close()
			}
			_ = resp.Body.Close()
			return nil, err
		}
		return conn, nil
	}
	if lastRoundTripErr != nil {
		if IsRetryableTCPStreamError(lastRoundTripErr) {
			host.ResetHTTP3Transport()
		}
		return nil, errors.Join(Errs.TCPConnectStreamFailed, lastRoundTripErr)
	}
	return nil, Errs.TCPConnectStreamFailed
}

func waitContextBackoff(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-t.C:
		return nil
	}
}

func dialH3LegLogSuffix(legLabel string) string {
	if legLabel == "" {
		return ""
	}
	return " dual_leg=" + legLabel
}

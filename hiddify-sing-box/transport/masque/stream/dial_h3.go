package stream

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go/http3"
	strmconn "github.com/sagernet/sing-box/transport/masque/stream/conn"
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
	NewRequestContext  func(parent context.Context) (ctx context.Context, stop func(success bool))
	BuildRequest       func(ctx context.Context, url, serverHost string) (*http.Request, error)
	TunnelFromResponse func(ctx context.Context, resp *http.Response, targetHost string, targetPort uint16) (net.Conn, error)
	RequestURL         func(u *url.URL) string
	ClassifyError      func(err error) string
	AuthFailed         error
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
	return DialHTTP3ConnectStreamLeg(ctx, hooks, host, tcpURL, logIn, targetHost, targetPort, tcpHTTP, "")
}

// DialHTTP3ConnectStreamLeg dials one CONNECT-stream leg (P2 dual dial).
func DialHTTP3ConnectStreamLeg(
	ctx context.Context,
	hooks DialH3Hooks,
	host DialH3Host,
	tcpURL *url.URL,
	logIn DialH3LogInput,
	targetHost string,
	targetPort uint16,
	tcpHTTP *http3.Transport,
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
		return nil, JoinConnectStreamPhase("connect handshake", context.Cause(ctx))
	default:
	}
	log.Printf("masque_http_layer_attempt layer=h3 tag=%s tcp_stream=1 target=%s dial=%s%s",
		strings.TrimSpace(logIn.Tag), tcpLogHost, dialAddr, dialH3LegLogSuffix(legLabel))
	maxAttempts := ConnectStreamDialMaxAttempts()
	var lastRoundTripErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctxErr := context.Cause(ctx); ctxErr != nil {
			return nil, JoinConnectStreamPhase("connect handshake", ctxErr)
		}
		streamCtx, stopReqCtxRelay := hooks.NewRequestContext(ctx)
		legCtx := ContextWithConnectStreamLeg(streamCtx, legLabel)
		if pairID := ConnectStreamPairFromContext(ctx); pairID != "" {
			legCtx = ContextWithConnectStreamPair(legCtx, pairID)
		}
		req, reqErr := hooks.BuildRequest(legCtx, hooks.RequestURL(tcpURL), serverHost)
		if reqErr != nil {
			stopReqCtxRelay(false)
			return nil, errors.Join(Errs.TCPConnectStreamFailed, reqErr)
		}
		// Request context can be canceled by detach/cascade boundary before RoundTrip starts.
		// Entering RoundTrip on an already-canceled request may still hit OpenStreamSync path.
		if reqCtxErr := context.Cause(req.Context()); reqCtxErr != nil {
			stopReqCtxRelay(false)
			return nil, JoinConnectStreamPhase("connect handshake", reqCtxErr)
		}
		roundTripper := host.RoundTripper(tcpHTTP)
		resp, roundTripErr := roundTripper.RoundTrip(req)
		if roundTripErr != nil {
			stopReqCtxRelay(false)
			lastRoundTripErr = roundTripErr
			if attempt+1 < maxAttempts && connectStreamRoundTripShouldRetry(roundTripErr) {
				// Overlay rebuild is session/hop-chain only (ResetTCPHTTPTransport).
				// Per-dial transport reset kills the shared QUIC conn and cascades
				// H3 error (0x0) (local) across parallel browser dials.
				if backoffErr := waitContextBackoff(ctx, ConnectStreamDialBackoff(attempt)); backoffErr != nil {
					return nil, JoinConnectStreamPhase("connect roundtrip backoff", backoffErr)
				}
				continue
			}
			return nil, JoinConnectStreamPhase("connect roundtrip", roundTripErr)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			stopReqCtxRelay(false)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				return nil, JoinConnectStreamHTTPStatus(hooks.AuthFailed, resp.StatusCode, hooks.RequestURL(tcpURL))
			}
			return nil, fmt.Errorf("%w: status=%d url=%s", Errs.TCPConnectStreamFailed, resp.StatusCode, hooks.RequestURL(tcpURL))
		}
		if ctxErr := context.Cause(ctx); ctxErr != nil {
			stopReqCtxRelay(false)
			_ = resp.Body.Close()
			return nil, JoinConnectStreamPhase("connect handshake", ctxErr)
		}
		conn, err := hooks.TunnelFromResponse(legCtx, resp, targetHost, targetPort)
		if err != nil {
			stopReqCtxRelay(false)
			_ = resp.Body.Close()
			return nil, err
		}
		// Detach after tunnel is wired; early detach can tear down the live H3 stream during bootstrap.
		stopReqCtxRelay(true)
		strmconn.SetStreamCancel(conn, func(error) { stopReqCtxRelay(false) })
		return conn, nil
	}
	if lastRoundTripErr != nil {
		return nil, JoinConnectStreamPhase("connect roundtrip", lastRoundTripErr)
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

package masque

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	M "github.com/sagernet/sing/common/metadata"
)

// Mirrors HTTP/3 CONNECT-stream semantics in dialTCPStream (there req.Proto becomes :protocol HTTP/3).
// On golang.org/x/net/http2, Extended CONNECT is triggered by req.Header.Set(":protocol", …); see RFC 8441.
const h2ConnectStreamProto = "HTTP/2"

var h2ConnectRequestContextFactory = connectip.NewH2ExtendedConnectRequestContext

func (s *coreSession) dialTCPStreamH2(ctx context.Context, tcpURL *url.URL, options ClientOptions, targetHost string, destination M.Socksaddr) (net.Conn, error) {
	serverHost := tcpURL.Host
	if serverHost == "" {
		serverHost = net.JoinHostPort(options.Server, strconv.Itoa(int(options.ServerPort)))
	}
	tcpLogHost := tcpURL.Host
	if tcpLogHost == "" {
		tcpLogHost = serverHost
	}

	portNum := int(options.ServerPort)
	if portNum <= 0 {
		portNum = 443
	}
	select {
	case <-ctx.Done():
		return nil, errors.Join(ErrTCPConnectStreamFailed, context.Cause(ctx))
	default:
	}
	dialAddr := masqueDialTarget(masqueQuicDialCandidateHost(options), portNum)
	log.Printf("masque_http_layer_attempt layer=h2 tag=%s tcp_stream=1 target=%s dial=%s", strings.TrimSpace(options.Tag), tcpLogHost, dialAddr)

	targetPort := destination.Port
	const maxAttempts = 3
	var lastRoundTripErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return nil, errors.Join(ErrTCPConnectStreamFailed, context.Cause(ctx))
		default:
		}
		tr, err := s.ensureH2UDPTransport(ctx)
		if err != nil {
			return nil, errors.Join(ErrTCPConnectStreamFailed, err)
		}
		tcpTracef("masque tcp connect_stream h2 host=%s port=%d attempt=%d", targetHost, targetPort, attempt+1)

		pr, pw := io.Pipe()
		streamCtx, stopReqCtxRelay := h2ConnectRequestContextFactory(ctx)
		req, reqErr := http.NewRequestWithContext(streamCtx, http.MethodConnect, MasqueTCPConnectStreamRequestURL(tcpURL), &h2ExtendedConnectUploadBody{pipe: pr})
		if reqErr != nil {
			stopReqCtxRelay(false)
			_ = pr.Close()
			_ = pw.Close()
			return nil, errors.Join(ErrTCPConnectStreamFailed, fmt.Errorf("masque h2: tcp connect-stream build request: %w", reqErr))
		}
		req.Host = serverHost
		req.Header = make(http.Header)
		req.Header.Set(":protocol", h2ConnectStreamProto)
		setMasqueAuthorizationHeader(req.Header, options)
		req.ContentLength = -1

		roundTripper := s.getTCPRoundTripper(tr)
		resp, roundTripErr := roundTripper.RoundTrip(req)
		if roundTripErr != nil {
			stopReqCtxRelay(false)
			lastRoundTripErr = roundTripErr
			_ = pr.Close()
			_ = pw.Close()
			if errors.Is(roundTripErr, context.Canceled) || errors.Is(roundTripErr, context.DeadlineExceeded) {
				tcpTracef("masque tcp connect_stream h2 cancelled host=%s port=%d attempt=%d error_class=%s err=%v", targetHost, targetPort, attempt+1, ClassifyError(ErrTCPConnectStreamFailed), roundTripErr)
				return nil, errors.Join(ErrTCPConnectStreamFailed, roundTripErr)
			}
			if attempt+1 < maxAttempts && isRetryableTCPStreamError(roundTripErr) && ctx.Err() == nil {
				tcpTracef("masque tcp connect_stream h2 retry host=%s port=%d attempt=%d error_class=%s err=%v", targetHost, targetPort, attempt+1, ClassifyError(ErrTCPConnectStreamFailed), roundTripErr)
				s.resetTCPHTTPTransport()
				if backoffErr := waitContextBackoff(ctx, time.Duration(attempt+1)*50*time.Millisecond); backoffErr != nil {
					return nil, errors.Join(ErrTCPConnectStreamFailed, backoffErr)
				}
				continue
			}
			tcpTracef("masque tcp connect_stream h2 failed host=%s port=%d status=roundtrip_error error_class=%s err=%v", targetHost, targetPort, ClassifyError(ErrTCPConnectStreamFailed), roundTripErr)
			return nil, errors.Join(ErrTCPConnectStreamFailed, fmt.Errorf("masque h2: tcp connect-stream roundtrip: %w", roundTripErr))
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			stopReqCtxRelay(false)
			_ = pr.Close()
			_ = pw.Close()
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				tcpTracef("masque tcp connect_stream h2 denied host=%s port=%d status=%d error_class=%s", targetHost, targetPort, resp.StatusCode, ClassifyError(ErrAuthFailed))
				return nil, errors.Join(ErrAuthFailed, fmt.Errorf("status=%d url=%s", resp.StatusCode, MasqueTCPConnectStreamRequestURL(tcpURL)))
			}
			tcpTracef("masque tcp connect_stream h2 failed host=%s port=%d status=%d error_class=%s", targetHost, targetPort, resp.StatusCode, ClassifyError(ErrTCPConnectStreamFailed))
			// Same shape as dialTCPStreamHTTP3 (%w: status=…) so logs and substring classifiers align.
			return nil, fmt.Errorf("masque h2: %w: status=%d url=%s", ErrTCPConnectStreamFailed, resp.StatusCode, MasqueTCPConnectStreamRequestURL(tcpURL))
		}
		if ctxErr := context.Cause(ctx); ctxErr != nil {
			stopReqCtxRelay(false)
			_ = pr.Close()
			_ = pw.Close()
			_ = resp.Body.Close()
			return nil, errors.Join(ErrTCPConnectStreamFailed, ctxErr)
		}
		stopReqCtxRelay(true)
		tcpTracef("masque tcp connect_stream h2 success host=%s port=%d status=%d", targetHost, targetPort, resp.StatusCode)
		remoteAddr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(targetHost, strconv.Itoa(int(destination.Port))))
		// Align streamConn semantics with the HTTP/2 CONNECT request context: the handshake may use a
		// short-lived dial ctx while Request.Context is WithoutCancel — using the dial ctx here would
		// mis-attribute transport errors via context.Cause after the handshake when the dial op ended.
		return &streamConn{
			reader:       newH2ConnectStreamResponseBody(resp.Body),
			writer:       pw,
			h2UploadPipe: pr,
			ctx:          streamCtx,
			local:        &net.TCPAddr{},
			remote:       remoteAddr,
		}, nil
	}
	if lastRoundTripErr != nil {
		return nil, errors.Join(ErrTCPConnectStreamFailed, lastRoundTripErr)
	}
	return nil, ErrTCPConnectStreamFailed
}

// h2ConnectStreamResponseBody wraps the HTTP/2 CONNECT response body (typically
// golang.org/x/net/http2.transportResponseBody), which does not implement SetReadDeadline.
// Without this, streamConn.SetReadDeadline would hit ErrDeadlineUnsupported on download I/O
// while upload-side pipe writes already honor deadlines (parity: h2ConnectUDPPacketConn).
type h2ConnectStreamResponseBody struct {
	r  io.ReadCloser
	dl connDeadlines
	mu sync.Mutex // serializes Read
}

func newH2ConnectStreamResponseBody(r io.ReadCloser) io.ReadCloser {
	if r == nil {
		return nil
	}
	return &h2ConnectStreamResponseBody{r: r}
}

func (w *h2ConnectStreamResponseBody) SetReadDeadline(t time.Time) error {
	w.dl.setReadDeadline(t)
	return nil
}

func (w *h2ConnectStreamResponseBody) Read(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dl.readTimeoutExceeded() {
		return 0, os.ErrDeadlineExceeded
	}
	rNanos := w.dl.read.Load()
	if rNanos == 0 {
		return w.r.Read(p)
	}
	if time.Now().UnixNano() > rNanos {
		return 0, os.ErrDeadlineExceeded
	}
	rctx, rcancel := context.WithDeadline(context.Background(), time.Unix(0, rNanos))
	defer rcancel()
	return w.awaitReadInterruptible(rctx, p)
}

// awaitReadInterruptible mirrors awaitH2UDPReqBodyWrite / h2ConnectUDPPacketConn.awaitParseH2UDPResponseCapsule
// so a blocked Read on the HTTP/2 response stream observes SetReadDeadline (Close tears the stream).
func (w *h2ConnectStreamResponseBody) awaitReadInterruptible(ctx context.Context, p []byte) (int, error) {
	ch := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := w.r.Read(p)
		ch <- struct {
			n   int
			err error
		}{n, err}
	}()
	select {
	case <-ctx.Done():
		_ = w.r.Close()
		got := <-ch
		_ = got
		if ce := context.Cause(ctx); errors.Is(ce, context.Canceled) {
			return 0, ce
		}
		return 0, os.ErrDeadlineExceeded
	case got := <-ch:
		return got.n, got.err
	}
}

func (w *h2ConnectStreamResponseBody) Close() error {
	if w.r == nil {
		return nil
	}
	return w.r.Close()
}

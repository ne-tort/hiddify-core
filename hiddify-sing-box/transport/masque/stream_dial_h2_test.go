package masque

import (
	"github.com/sagernet/sing-box/transport/masque/session"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

type streamDialH2FakeHost struct {
	ensureErr atomic.Pointer[error]
	tr        http.RoundTripper
	rt        http.RoundTripper
	resetN    atomic.Uint32
}

func (h *streamDialH2FakeHost) EnsureH2ConnectStreamTransport(context.Context) (http.RoundTripper, error) {
	if p := h.ensureErr.Load(); p != nil {
		return nil, *p
	}
	if h.tr != nil {
		return h.tr, nil
	}
	return http.DefaultTransport, nil
}

func (h *streamDialH2FakeHost) RoundTripper(defaultTransport http.RoundTripper) http.RoundTripper {
	if h.rt != nil {
		return h.rt
	}
	return defaultTransport
}

func (h *streamDialH2FakeHost) ResetH2ConnectStreamTransport() {
	h.resetN.Add(1)
}

func testStreamDialH2Hooks() strm.DialH2Hooks {
	return strm.DialH2Hooks{
		NewRequestContext: func(parent context.Context) (context.Context, func(bool)) {
			return parent, func(bool) {}
		},
		NewConnectUploadBody: func(pr *io.PipeReader) io.Reader { return pr },
		RequestURL:           func(u *url.URL) string { return u.String() },
		TunnelFromResponse: func(ctx context.Context, resp *http.Response, upload *io.PipeWriter, uploadBody io.Reader, targetHost string, targetPort uint16) (net.Conn, error) {
			return nil, session.ErrTCPConnectStreamFailed
		},
		ClassifyError: func(err error) string { return string(session.ClassifyError(err)) },
		AuthFailed:    session.ErrAuthFailed,
	}
}

func TestStreamDialHTTP2ConnectStreamReturnsCanceledBeforeAttempt(t *testing.T) {
	u, err := url.Parse("https://example.com/masque/tcp")
	if err != nil {
		t.Fatalf("parse tcp url: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, dialErr := strm.DialHTTP2ConnectStream(ctx, testStreamDialH2Hooks(), &streamDialH2FakeHost{}, u, strm.DialH2LogInput{
		Tag:        "t",
		Server:     "127.0.0.1",
		ServerPort: 443,
	}, "example.com", 80)
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", dialErr)
	}
	if !errors.Is(dialErr, session.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected session.ErrTCPConnectStreamFailed joined, got %v", dialErr)
	}
}

func TestStreamDialHTTP2ConnectStreamReturnsCanceledAfterRoundTripSuccess(t *testing.T) {
	u, err := url.Parse("https://example.com/masque/tcp")
	if err != nil {
		t.Fatalf("parse tcp url: %v", err)
	}
	var attempts atomic.Uint32
	ctx, cancel := context.WithCancel(context.Background())
	host := &streamDialH2FakeHost{
		rt: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			attempts.Add(1)
			cancel()
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		}),
	}
	_, dialErr := strm.DialHTTP2ConnectStream(ctx, testStreamDialH2Hooks(), host, u, strm.DialH2LogInput{
		Tag:        "t",
		Server:     "127.0.0.1",
		ServerPort: 443,
	}, "example.com", 443)
	if dialErr == nil {
		t.Fatal("expected canceled error")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", dialErr)
	}
	if !errors.Is(dialErr, session.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected session.ErrTCPConnectStreamFailed joined, got %v", dialErr)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("expected single RoundTrip attempt, got %d", got)
	}
}

func TestStreamDialHTTP2ConnectStreamJoinsErrWhenTransportUnconfigured(t *testing.T) {
	u, err := url.Parse("https://example.com/masque/tcp/example.com/443")
	if err != nil {
		t.Fatalf("parse tcp url: %v", err)
	}
	host := &streamDialH2FakeHost{}
	ensureErr := errors.New("tcp dialer is not configured")
	host.ensureErr.Store(&ensureErr)
	_, dialErr := strm.DialHTTP2ConnectStream(context.Background(), testStreamDialH2Hooks(), host, u, strm.DialH2LogInput{
		Tag:        "t",
		Server:     "127.0.0.1",
		ServerPort: 443,
	}, "example.com", 443)
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, session.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected session.ErrTCPConnectStreamFailed joined, got %v", dialErr)
	}
	if !strings.Contains(dialErr.Error(), "tcp dialer is not configured") {
		t.Fatalf("expected tcp dialer error substring, got %v", dialErr)
	}
}

func TestStreamDialHTTP2ConnectStreamResetsOverlayAfterRetryExhausted(t *testing.T) {
	u, err := url.Parse("https://example.com/masque/tcp/example.com/443")
	if err != nil {
		t.Fatalf("parse tcp url: %v", err)
	}
	var attempts atomic.Uint32
	retryErr := errors.New("connection reset by peer")
	host := &streamDialH2FakeHost{
		rt: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			attempts.Add(1)
			return nil, retryErr
		}),
	}
	_, dialErr := strm.DialHTTP2ConnectStream(context.Background(), testStreamDialH2Hooks(), host, u, strm.DialH2LogInput{
		Tag:        "t",
		Server:     "127.0.0.1",
		ServerPort: 443,
	}, "example.com", 443)
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, session.ErrTCPConnectStreamFailed) {
		t.Fatalf("expected session.ErrTCPConnectStreamFailed joined, got %v", dialErr)
	}
	if got := attempts.Load(); got != 5 {
		t.Fatalf("expected 5 RoundTrip attempts, got %d", got)
	}
	if got := host.resetN.Load(); got != 5 {
		t.Fatalf("expected overlay reset on each retry plus final failure (resets=5), got %d", got)
	}
}

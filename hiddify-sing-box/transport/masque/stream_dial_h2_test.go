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

	strmclient "github.com/sagernet/sing-box/transport/masque/stream/client"
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
	hooks := strmclient.NewH2Hooks(strmclient.H2Wire{
		RequestURL: func(u *url.URL) string { return u.String() },
	})
	hooks.TunnelFromResponse = func(ctx context.Context, resp *http.Response, upload io.WriteCloser, uploadBody io.Reader, targetHost string, targetPort uint16) (net.Conn, error) {
		_ = resp
		_ = upload
		_ = uploadBody
		return nil, session.ErrTCPConnectStreamFailed
	}
	return hooks
}

func TestStreamDialH2HooksRequireUploadPipe(t *testing.T) {
	t.Parallel()
	u, err := url.Parse("https://example.com/stream")
	if err != nil {
		t.Fatal(err)
	}
	hooks := testStreamDialH2Hooks()
	hooks.NewConnectUploadPipe = nil
	_, dialErr := strm.DialHTTP2ConnectStream(context.Background(), hooks, &streamDialH2FakeHost{}, u, strm.DialH2LogInput{
		Server: "example.com", ServerPort: 443,
	}, "target", 443)
	if dialErr == nil {
		t.Fatal("expected error when upload pipe hook missing")
	}
	if !strings.Contains(dialErr.Error(), "upload pipe hook required") {
		t.Fatalf("unexpected error: %v", dialErr)
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
	wantAttempts := uint32(strm.ConnectStreamDialMaxAttempts())
	if got := attempts.Load(); got != wantAttempts {
		t.Fatalf("expected %d RoundTrip attempts, got %d", wantAttempts, got)
	}
	// Reset runs between failed attempts, not after the final failure.
	wantResets := wantAttempts - 1
	if got := host.resetN.Load(); got != wantResets {
		t.Fatalf("expected overlay reset between retries (resets=%d), got %d", wantResets, got)
	}
}

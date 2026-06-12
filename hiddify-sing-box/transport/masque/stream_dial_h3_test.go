package masque

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/quic-go/quic-go/http3"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

type streamDialH3FakeHost struct {
	rt         http.RoundTripper
	resetN     atomic.Uint32
	afterReset *http3.Transport
}

func (h *streamDialH3FakeHost) RoundTripper(defaultTransport http.RoundTripper) http.RoundTripper {
	if h.rt != nil {
		return h.rt
	}
	return defaultTransport
}

func (h *streamDialH3FakeHost) ResetHTTP3Transport() *http3.Transport {
	h.resetN.Add(1)
	return h.afterReset
}

func testStreamDialH3Hooks() strm.DialH3Hooks {
	return strm.DialH3Hooks{
		NewRequestContext: func(parent context.Context) (context.Context, func(bool)) {
			return parent, func(bool) {}
		},
		BuildRequest: func(ctx context.Context, rawURL, serverHost string, usePipe bool) (*http.Request, *io.PipeReader, io.WriteCloser, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodConnect, rawURL, nil)
			if err != nil {
				return nil, nil, nil, err
			}
			return req, nil, nil, nil
		},
		TunnelFromResponse: func(ctx context.Context, resp *http.Response, upload io.WriteCloser, targetHost string, targetPort uint16) (net.Conn, error) {
			return nil, ErrTCPConnectStreamFailed
		},
		UsePipeUpload: func() bool { return false },
		RequestURL:    func(u *url.URL) string { return u.String() },
		ClassifyError: func(err error) string { return string(ClassifyError(err)) },
		AuthFailed:    ErrAuthFailed,
	}
}

func TestStreamDialHTTP3ConnectStreamReturnsCanceledBeforeAttempt(t *testing.T) {
	u, err := url.Parse("https://example.com/masque/tcp")
	if err != nil {
		t.Fatalf("parse tcp url: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, dialErr := strm.DialHTTP3ConnectStream(ctx, testStreamDialH3Hooks(), &streamDialH3FakeHost{}, u, strm.DialH3LogInput{
		Tag:        "t",
		Server:     "127.0.0.1",
		ServerPort: 443,
	}, "example.com", 80, nil)
	if dialErr == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", dialErr)
	}
	if !errors.Is(dialErr, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed joined, got %v", dialErr)
	}
}

func TestStreamDialHTTP3ConnectStreamReturnsCanceledAfterRoundTripSuccess(t *testing.T) {
	u, err := url.Parse("https://example.com/masque/tcp")
	if err != nil {
		t.Fatalf("parse tcp url: %v", err)
	}
	var attempts atomic.Uint32
	ctx, cancel := context.WithCancel(context.Background())
	host := &streamDialH3FakeHost{
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
	_, dialErr := strm.DialHTTP3ConnectStream(ctx, testStreamDialH3Hooks(), host, u, strm.DialH3LogInput{
		Tag:        "t",
		Server:     "127.0.0.1",
		ServerPort: 443,
	}, "example.com", 443, nil)
	if dialErr == nil {
		t.Fatal("expected canceled error")
	}
	if !errors.Is(dialErr, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", dialErr)
	}
	if !errors.Is(dialErr, ErrTCPConnectStreamFailed) {
		t.Fatalf("expected ErrTCPConnectStreamFailed joined, got %v", dialErr)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("expected single RoundTrip attempt, got %d", got)
	}
}

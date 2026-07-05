package masque

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/quic-go/quic-go/http3"
	connectip "github.com/quic-go/connect-ip-go"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	strmconn "github.com/sagernet/sing-box/transport/masque/stream/conn"
)

type dialH3CancelFakeHost struct {
	rt http.RoundTripper
}

func (h *dialH3CancelFakeHost) RoundTripper(defaultTransport http.RoundTripper) http.RoundTripper {
	if h.rt != nil {
		return h.rt
	}
	return defaultTransport
}

func (h *dialH3CancelFakeHost) ResetHTTP3Transport() *http3.Transport { return nil }

type dialH3GateUpload struct{ io.Writer }

func (dialH3GateUpload) Close() error { return nil }

// TestGATEH3DialConnectStreamCloseCancelsDetachedRequestContext (GATE-SYNTH-CANCEL) — prod
// NewH2ExtendedConnectRequestContext + SetStreamCancel wiring: Close after detach must cancel reqCtx.
func TestGATEH3DialConnectStreamCloseCancelsDetachedRequestContext(t *testing.T) {
	u, err := url.Parse("https://example.com/masque/tcp/h/p")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var reqCtx context.Context
	hooks := strm.DialH3Hooks{
		NewRequestContext: connectip.NewH2ExtendedConnectRequestContext,
		BuildRequest: func(ctx context.Context, rawURL, serverHost string) (*http.Request, error) {
			reqCtx = ctx
			return http.NewRequestWithContext(ctx, http.MethodConnect, rawURL, nil)
		},
		TunnelFromResponse: func(context.Context, *http.Response, string, uint16) (net.Conn, error) {
			return strmconn.ConnFromTunnelPaths(context.Background(), strmconn.TunnelPaths{
				Download: strmconn.NewDownloadPathAdapter(io.NopCloser(strings.NewReader("ok"))),
				Upload:   strmconn.NewUploadPath(dialH3GateUpload{io.Discard}),
			}, &net.TCPAddr{}, &net.TCPAddr{Port: 443}), nil
		},
		RequestURL:    func(u *url.URL) string { return u.String() },
		ClassifyError: func(err error) string { return err.Error() },
	}
	var trips atomic.Uint32
	host := &dialH3CancelFakeHost{
		rt: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			trips.Add(1)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		}),
	}
	conn, dialErr := strm.DialHTTP3ConnectStream(context.Background(), hooks, host, u, strm.DialH3LogInput{
		Tag: "t", Server: "127.0.0.1", ServerPort: 443,
	}, "127.0.0.1", 80, nil)
	if dialErr != nil {
		t.Fatalf("dial: %v", dialErr)
	}
	if reqCtx == nil {
		t.Fatal("reqCtx not captured")
	}
	select {
	case <-reqCtx.Done():
		t.Fatal("reqCtx canceled before Close teardown")
	default:
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-reqCtx.Done():
	default:
		t.Fatal("reqCtx must cancel after tunnel Close (SetStreamCancel → stop(false))")
	}
	if trips.Load() != 1 {
		t.Fatalf("expected 1 RoundTrip, got %d", trips.Load())
	}
}

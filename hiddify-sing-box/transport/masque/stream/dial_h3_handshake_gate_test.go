package stream

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	connectip "github.com/quic-go/connect-ip-go"
	strmconn "github.com/sagernet/sing-box/transport/masque/stream/conn"
)

type dialH3HandshakeGateHost struct {
	rt http.RoundTripper
}

func (h *dialH3HandshakeGateHost) RoundTripper(defaultTransport http.RoundTripper) http.RoundTripper {
	if h.rt != nil {
		return h.rt
	}
	return defaultTransport
}

func (h *dialH3HandshakeGateHost) ResetHTTP3Transport() *http3.Transport { return nil }

type dialH3GateUpload struct{ io.Writer }

func (dialH3GateUpload) Close() error { return nil }

// TestGATEH3DialConnectStreamParentCancelDuringHandshakeSucceeds verifies that a
// parent dial cancel during RoundTrip does not fail a completed CONNECT handshake.
func TestGATEH3DialConnectStreamParentCancelDuringHandshakeSucceeds(t *testing.T) {
	u, err := url.Parse("https://example.com/masque/tcp/h/p")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	parent, parentCancel := context.WithCancel(context.Background())
	ctx, cancelHandshake := ConnectStreamHandshakeContext(parent)
	defer cancelHandshake()

	hooks := DialH3Hooks{
		NewRequestContext: connectip.NewH2ExtendedConnectRequestContext,
		BuildRequest: func(ctx context.Context, rawURL, serverHost string) (*http.Request, error) {
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
	host := &dialH3HandshakeGateHost{
		rt: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			trips.Add(1)
			parentCancel()
			time.Sleep(20 * time.Millisecond)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		}),
	}
	conn, dialErr := DialHTTP3ConnectStream(ctx, hooks, host, u, DialH3LogInput{
		Tag: "t", Server: "127.0.0.1", ServerPort: 443,
	}, "127.0.0.1", 80, nil)
	if dialErr != nil {
		t.Fatalf("dial after parent cancel during RoundTrip: %v", dialErr)
	}
	if conn == nil {
		t.Fatal("nil conn")
	}
	_ = conn.Close()
	if trips.Load() != 1 {
		t.Fatalf("trips=%d", trips.Load())
	}
}

func TestGATEH3DialConnectStreamCanceledRequestCtxSkipsRoundTrip(t *testing.T) {
	u, err := url.Parse("https://example.com/masque/tcp/h/p")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var roundTrips atomic.Int32
	hooks := DialH3Hooks{
		NewRequestContext: func(parent context.Context) (context.Context, func(bool)) {
			reqCtx, reqCancel := context.WithCancel(parent)
			reqCancel()
			return reqCtx, func(bool) {}
		},
		BuildRequest: func(ctx context.Context, rawURL, serverHost string) (*http.Request, error) {
			return http.NewRequestWithContext(ctx, http.MethodConnect, rawURL, nil)
		},
		TunnelFromResponse: func(context.Context, *http.Response, string, uint16) (net.Conn, error) {
			return nil, context.Canceled
		},
		RequestURL:    func(u *url.URL) string { return u.String() },
		ClassifyError: func(err error) string { return err.Error() },
	}
	host := &dialH3HandshakeGateHost{
		rt: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			roundTrips.Add(1)
			return nil, context.Canceled
		}),
	}
	_, dialErr := DialHTTP3ConnectStream(ctx, hooks, host, u, DialH3LogInput{
		Tag: "t", Server: "127.0.0.1", ServerPort: 443,
	}, "127.0.0.1", 443, nil)
	if dialErr == nil {
		t.Fatal("expected canceled request context error")
	}
	if roundTrips.Load() != 0 {
		t.Fatalf("RoundTrip should be skipped for canceled request ctx, got %d call(s)", roundTrips.Load())
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

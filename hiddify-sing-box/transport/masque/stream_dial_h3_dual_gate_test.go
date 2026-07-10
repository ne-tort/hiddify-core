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
	strmclient "github.com/sagernet/sing-box/transport/masque/stream/client"
	strmconn "github.com/sagernet/sing-box/transport/masque/stream/conn"
)

type dualConnectGateHost struct {
	rt http.RoundTripper
}

func (h *dualConnectGateHost) RoundTripper(defaultTransport http.RoundTripper) http.RoundTripper {
	if h.rt != nil {
		return h.rt
	}
	return defaultTransport
}

func (h *dualConnectGateHost) ResetHTTP3Transport() *http3.Transport { return nil }

type dualConnectGateUpload struct{ io.Writer }

func (dualConnectGateUpload) Close() error { return nil }

// TestGATEH3DualConnectSurvivesHandshakeScopeEnd (GATE-SYNTH-DUAL-SCOPE) — DualTunnelConn must
// outlive ConnectStreamHandshakeContext cancel (dialTCPStream defer handshakeCancel).
func TestGATEH3DualConnectSurvivesHandshakeScopeEnd(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_STREAM_DUAL_CONNECT", "1")
	u, err := url.Parse("https://example.com/masque/tcp/h/p")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	hooks := strmclient.NewH3Hooks(strmclient.H3Wire{
		NewRequestContext: connectip.NewH2ExtendedConnectRequestContext,
		RequestURL:        func(u *url.URL) string { return u.String() },
	})
	hooks.TunnelFromResponse = func(context.Context, *http.Response, string, uint16) (net.Conn, error) {
		return strmconn.ConnFromTunnelPaths(context.Background(), strmconn.TunnelPaths{
			Download: strmconn.NewDownloadPathAdapter(io.NopCloser(strings.NewReader("ok"))),
			Upload:   strmconn.NewUploadPath(dualConnectGateUpload{io.Discard}),
		}, &net.TCPAddr{}, &net.TCPAddr{Port: 443}), nil
	}
	var trips atomic.Uint32
	host := &dualConnectGateHost{
		rt: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			trips.Add(1)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		}),
	}
	var conn net.Conn
	var dialErr error
	func() {
		handshakeCtx, cancelHandshake := strm.ConnectStreamHandshakeContext(context.Background())
		defer cancelHandshake()
		conn, dialErr = strmclient.DialHTTP3(handshakeCtx, hooks, host, u, strmclient.H3DialInput{
			Tag: "t", Server: "127.0.0.1", ServerPort: 443,
		}, nil)
	}()
	if dialErr != nil {
		t.Fatalf("dual dial: %v", dialErr)
	}
	defer conn.Close()
	if trips.Load() != 2 {
		t.Fatalf("expected 2 CONNECT legs, got %d", trips.Load())
	}
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("upload after handshake scope end: %v", err)
	}
}

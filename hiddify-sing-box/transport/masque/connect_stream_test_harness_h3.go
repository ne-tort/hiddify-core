package masque

// H3 CONNECT-stream in-process test harness (W-STR-4 PR6).

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	h3HonestGateMinBytes = 32 * 1024
	h3HonestGateDuration = 12 * time.Second
)

func newConnectStreamH3ProdSession(t *testing.T, proxyPort int) (ClientSession, context.Context) {
	return newConnectStreamH3ProdSessionWithTimeout(t, proxyPort, 10*time.Second)
}

func newConnectStreamH3ProdSessionWithTimeout(t *testing.T, proxyPort int, timeout time.Duration) (ClientSession, context.Context) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(proxyPort),
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
		MasqueQUICCryptoTLS:      &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("new connect-stream-h3 session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, waitCtx
}

func dialConnectStreamH3ProdTCP(t *testing.T, proxyPort int, targetPort uint16) net.Conn {
	t.Helper()
	session, ctx := newConnectStreamH3ProdSession(t, proxyPort)
	return dialConnectStreamH3ProdTCPWithSession(t, session, ctx, targetPort)
}

func dialConnectStreamH3ProdTCPWithSession(t *testing.T, session ClientSession, ctx context.Context, targetPort uint16) net.Conn {
	t.Helper()
	conn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", targetPort))
	if err != nil {
		t.Fatalf("dial connect-stream-h3 prod tcp: %v", err)
	}
	return conn
}

func newConnectStreamH3DockerLiveSession(t *testing.T) ClientSession {
	t.Helper()
	if os.Getenv("DOCKER_LIVE_SERVER") != "1" {
		t.Skip("set DOCKER_LIVE_SERVER=1 with masque-perf-lab up")
	}
	host := strings.TrimSpace(os.Getenv("DOCKER_MASQUE_SERVER"))
	if host == "" {
		host = "masque-server-core"
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:                   host,
		ServerPort:               8443,
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
		MasqueQUICCryptoTLS:      &tls.Config{ServerName: host, InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("docker live connect-stream-h3 session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func startH3ConnectStreamSocksRouter(t *testing.T, proxyPort int) uint16 {
	t.Helper()
	session, _ := newConnectStreamH3ProdSession(t, proxyPort)
	return startH3ConnectStreamSocksRouterWithSession(t, session)
}

func startH3ConnectStreamSocksRouterWithSession(t *testing.T, session ClientSession) uint16 {
	t.Helper()
	out := &masqueSessionOutbound{
		Adapter: outbound.NewAdapter(C.TypeMasque, "masque-out", []string{N.NetworkTCP, N.NetworkUDP}, nil),
		sess:    session,
	}
	cm := route.NewConnectionManager(log.StdLogger())
	t.Cleanup(func() { _ = cm.Close() })
	router := &directMasqueRouter{cm: cm, dialer: out}
	return startSocks5AssociateRelay(t, router, C.TypeSOCKS)
}

func dialH3ConnectStreamBench(tb testing.TB, targetPort int) net.Conn {
	tb.Helper()
	proxyPort := startInProcessTCPConnectStreamRelayProxy(tb)
	waitCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	tb.Cleanup(cancel)

	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		tb.Fatalf("new session: %v", err)
	}
	tb.Cleanup(func() { _ = session.Close() })

	targetAddr := M.ParseSocksaddrHostPort("127.0.0.1", uint16(targetPort))
	conn, err := session.DialContext(waitCtx, "tcp", targetAddr)
	if err != nil {
		tb.Fatalf("dial connect-stream: %v", err)
	}
	tb.Cleanup(func() { _ = conn.Close() })
	return benchWindowedBidiLinkStrictH3().wrap(conn)
}

func runH3HonestGateDuplexWriteTo(t *testing.T, conn net.Conn, duration time.Duration, minBytes int64) int64 {
	t.Helper()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		control := make([]byte, 64)
		for i := range control {
			control[i] = 'C'
		}
		ticker := time.NewTicker(30 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if _, err := conn.Write(control); err != nil {
					return
				}
			}
		}
	}()

	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, _, err := measureTCPDownloadWriteToMbps(conn, duration)
		done <- result{n: n, err: err}
	}()

	select {
	case r := <-done:
		if r.err != nil && r.n == 0 {
			t.Fatalf("honest gate WriteTo: %v", r.err)
		}
		return r.n
	case <-time.After(duration + 5*time.Second):
		t.Fatal("honest gate WriteTo blocked past deadline (H3 bidi FC stall)")
		return 0
	}
}

func runH3SocksFakeIperfNoPulse(t *testing.T, proxyPort int, targetPort uint16, minBytes int64) int64 {
	t.Helper()
	socksPort := startH3ConnectStreamSocksRouter(t, proxyPort)
	conn := socksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	banner := make([]byte, 8)
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("read fake iperf banner: %v", err)
	}
	if string(banner) != "iperf3\r\n" {
		t.Fatalf("banner: got %q", string(banner))
	}
	if _, err := conn.Write([]byte("FAKEIPERF")); err != nil {
		t.Fatalf("write fake iperf params: %v", err)
	}

	var dst bytes.Buffer
	n, err := io.Copy(&dst, conn)
	if err != nil && n == 0 {
		t.Fatalf("fake iperf download: %v", err)
	}
	if n < minBytes {
		t.Fatalf("fake iperf download short: %d want >= %d", n, minBytes)
	}
	if !strings.HasPrefix(dst.String(), "BBBB") {
		t.Fatalf("fake iperf bulk prefix lost: got %q", dst.String()[:min(len(dst.String()), 16)])
	}
	return n
}

func runH3SocksRealIperf3UploadFirst(t *testing.T, proxyPort int, targetPort uint16, minBytes int64) int64 {
	t.Helper()
	socksPort := startH3ConnectStreamSocksRouter(t, proxyPort)
	conn := socksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	cookie := testIperf3ClientCookie()
	params := testIperf3ClientParamsJSON(cookie)

	if _, err := conn.Write(cookie); err != nil {
		t.Fatalf("write iperf3 cookie: %v", err)
	}
	if _, err := conn.Write(params); err != nil {
		t.Fatalf("write iperf3 params: %v", err)
	}

	var dst bytes.Buffer
	n, err := io.Copy(&dst, conn)
	if err != nil && n == 0 {
		t.Fatalf("real iperf3 download: %v", err)
	}
	if n < minBytes {
		t.Fatalf("real iperf3 download short: %d want >= %d", n, minBytes)
	}
	return n
}

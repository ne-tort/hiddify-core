package masque

// In-process CONNECT-UDP test harness (H3 HTTP/3 proxy + UDP echo/sink). Used by masque gate/localize
// tests and connectudp/inttest (W-UDP-4 PR3). Not a stable public API.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	cudpserver "github.com/sagernet/sing-box/protocol/masque/server/connectudp"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	cudpframe "github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

// connectUDPTestServerHandler mirrors protocol/masque/server/connect_udp.go default hooks
// without importing protocol/masque/server (import cycle with transport/masque).
var connectUDPTestServerHandler = cudpserver.Handler{
	Hooks: cudpserver.Hooks{
		ResolveTCPTarget: func(_ context.Context, host string, allowPrivate bool) (string, error) {
			if allowPrivate {
				return strings.Trim(strings.TrimSpace(host), "[]"), nil
			}
			return "", connectudp.ErrPrivateTargetDenied
		},
		AllowTCPPort: func(_ string, _, _ []uint16) bool { return true },
		CapsuleProtocolHeaderValue: func() string {
			return cudpframe.CapsuleProtocolHeaderValue
		},
	},
}

func connectUDPTestTargetPolicy() cudpserver.TargetPolicy {
	return cudpserver.TargetPolicy{AllowPrivateTargets: true}
}

func serveConnectUDPProdHandler(w http.ResponseWriter, r *http.Request, udpTemplate *uritemplate.Template, udpProxy *cudprelay.Proxy, handler ...cudpserver.Handler) {
	req, err := cudpframe.ParseRequest(r, udpTemplate)
	if err != nil {
		if pe, ok := err.(*cudpframe.RequestParseError); ok {
			w.WriteHeader(pe.HTTPStatus)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	h := connectUDPTestServerHandler
	if len(handler) > 0 {
		h = handler[0]
	}
	h.HandleConnectUDP(w, r, req, udpProxy, connectUDPTestTargetPolicy())
}

func newConnectUDPH3ProdListenPacket(tb testing.TB, target M.Socksaddr) (net.PacketConn, func()) {
	return newConnectUDPH3ProdListenPacketWithRegister(tb, target, registerMasqueUDPProxyHandler)
}

func newConnectUDPH3ProdListenPacketWithRegister(
	tb testing.TB,
	target M.Socksaddr,
	register func(testing.TB, *http.ServeMux, int),
) (net.PacketConn, func()) {
	tb.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	proxyPort := startInProcessMasqueUDPProxy(tb, func(mux *http.ServeMux, proxyPort int) {
		register(tb, mux, proxyPort)
	})
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		cancel()
		tb.Fatalf("session: %v", err)
	}
	pkt, err := session.ListenPacket(waitCtx, target)
	if err != nil {
		_ = session.Close()
		cancel()
		tb.Fatalf("ListenPacket: %v", err)
	}
	cleanup := func() {
		_ = pkt.Close()
		_ = session.Close()
		cancel()
	}
	tb.Cleanup(cleanup)
	return pkt, cleanup
}

func runUDPEcho(t testing.TB, addr *net.UDPAddr) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen echo udp: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, raddr, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := c.WriteTo(buf[:n], raddr); err != nil {
				return
			}
		}
	}()
	return c
}

func runUDPSink(t testing.TB, addr *net.UDPAddr) (*net.UDPConn, *atomic.Int64) {
	t.Helper()
	c, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen sink udp: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	const sinkReadBuf = 64 * 1024
	_ = c.SetReadBuffer(4 << 20)
	var received atomic.Int64
	go func() {
		buf := make([]byte, sinkReadBuf)
		for {
			n, _, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			received.Add(int64(n))
		}
	}()
	return c, &received
}

// startInProcessMasqueUDPProxy serves HTTP/3 on an ephemeral UDP port. register must add handlers
// (typically /masque/udp/{target_host}/{target_port}) and own proxy-side Close hooks via t.Cleanup.
func startInProcessMasqueUDPProxy(t testing.TB, register func(mux *http.ServeMux, proxyPort int)) int {
	t.Helper()
	quicConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen quic udp: %v", err)
	}
	t.Cleanup(func() { quicConn.Close() })
	proxyPort := quicConn.LocalAddr().(*net.UDPAddr).Port

	mux := http.NewServeMux()
	register(mux, proxyPort)
	server := http3.Server{
		TLSConfig:       connectUDPTestTLS,
		QUICConfig:      h3t.HTTPServerQUICConfig(),
		EnableDatagrams: true,
		Handler:         mux,
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(quicConn) }()
	waitInProcessMasqueUDPProxyReady(t, proxyPort)
	return proxyPort
}

func waitInProcessMasqueUDPProxyReady(tb testing.TB, port int) {
	tb.Helper()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialUDP("udp", nil, addr)
		if err == nil {
			_ = c.Close()
			return
		}
	}
	tb.Fatal("in-process MASQUE UDP proxy not ready")
}

func registerMasqueUDPProxyHandler(t testing.TB, mux *http.ServeMux, proxyPort int) {
	t.Helper()
	templateRaw := fmt.Sprintf("https://127.0.0.1:%d/masque/udp/{target_host}/{target_port}", proxyPort)
	udpTemplate, err := uritemplate.New(templateRaw)
	if err != nil {
		t.Fatalf("udp template: %v", err)
	}
	var udpProxy cudprelay.Proxy
	t.Cleanup(func() { _ = udpProxy.Close() })
	mux.HandleFunc("/masque/udp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		serveConnectUDPProdHandler(w, r, udpTemplate, &udpProxy)
	})
}

func startInProcessMasqueUDPProxyWithRelay(t testing.TB) int {
	t.Helper()
	return startInProcessMasqueUDPProxyWithRelayPolicy(t, cudprelay.RelayPayloadProd)
}

func startInProcessMasqueUDPProxyWithRelayPolicy(t testing.TB, policy cudprelay.RelayPayloadPolicy) int {
	t.Helper()
	prev := cudprelay.RelayPayloadPolicyCurrent()
	cudprelay.SetRelayPayloadPolicy(policy)
	if policy != prev {
		t.Cleanup(func() { cudprelay.SetRelayPayloadPolicy(prev) })
	}
	return startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})
}

func startInProcessMasqueUDPProxyForbidden(t testing.TB) int {
	t.Helper()
	return startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		templateRaw := fmt.Sprintf("https://127.0.0.1:%d/masque/udp/{target_host}/{target_port}", proxyPort)
		udpTemplate, err := uritemplate.New(templateRaw)
		if err != nil {
			t.Fatalf("udp template: %v", err)
		}
		mux.HandleFunc("/masque/udp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
			if _, err := cudpframe.ParseRequest(r, udpTemplate); err != nil {
				if pe, ok := err.(*cudpframe.RequestParseError); ok {
					w.WriteHeader(pe.HTTPStatus)
					return
				}
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusForbidden)
		})
	})
}

func startConnectUDPMasqueSession(tb testing.TB, proxyPort int) ClientSession {
	tb.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	tb.Cleanup(cancel)
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		tb.Fatalf("new connect_udp session: %v", err)
	}
	tb.Cleanup(func() { closeConnectUDPTestSession(session) })
	return session
}

// trackConnectUDPGoroutines fails the test if goroutines remain after cleanup (selector/outbound close contract).
func trackConnectUDPGoroutines(t *testing.T) {
	t.Helper()
	runtime.GC()
	start := goroutineCount()
	t.Cleanup(func() {
		if t.Failed() {
			return
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			runtime.GC()
			if goroutineCount() <= start {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		end := goroutineCount()
		if end > start {
			t.Fatalf("connect-udp goroutine leak: start=%d end=%d\n%s", start, end, goroutineStacks())
		}
	})
}

func goroutineCount() int {
	return pprof.Lookup("goroutine").Count()
}

func goroutineStacks() string {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return string(buf[:n])
}

// ConnectUDPTestFactory is the exported session factory for connectudp integration tests.
type ConnectUDPTestFactory = CoreClientFactory

// NewConnectUDPTestSession builds a core MASQUE client session for CONNECT-UDP gate/localize tests.
func NewConnectUDPTestSession(ctx context.Context, opts ClientOptions) (ClientSession, error) {
	return (CoreClientFactory{}).NewSession(ctx, opts)
}

// ResetConnectUDPH2TransportForTest closes the cached CONNECT-UDP H2 http2.Transport on a session.
// Synth tests reuse CoreClientFactory sessions in-process; reset avoids stale pooled conns between cases.
func ResetConnectUDPH2TransportForTest(sess ClientSession) {
	s, ok := sess.(*coreSession)
	if !ok || s == nil {
		return
	}
	s.Mu.Lock()
	s.resetH2UDPTransportLockedAssumeMu()
	s.Mu.Unlock()
}

// closeConnectUDPTestSession closes a synth session and resets H2 transport cache when applicable.
func closeConnectUDPTestSession(sess ClientSession) {
	if sess == nil {
		return
	}
	_ = sess.Close()
	ResetConnectUDPH2TransportForTest(sess)
}

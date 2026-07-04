package masque_test

// GATE-DOCKER-H3 prod-stack synth (LaunchMasqueStack + SOCKS/CM). Non-GATE prod-stack → stream/inttest/.

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque/server"
	"github.com/sagernet/sing-box/transport/masque"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	"github.com/yosida95/uritemplate/v3"

	_ "github.com/sagernet/sing-box/internal/http2xconnect"
)

const (
	h3ProdStackFakeIperfMinBytes = 32 * 1024
	h3DockerSynthStallWatchdog   = 10 * time.Second
	h3DockerSynthDownloadBench   = 2 * time.Second
	prodStackTestShutdownTimeout   = 400 * time.Millisecond // synth tests: avoid 8s HTTP/2 graceful drain
)

func startLaunchMasqueStackH3ConnectStreamServer(t *testing.T) int {
	t.Helper()
	var tcpTemplate *uritemplate.Template
	mux := http.NewServeMux()
	mux.HandleFunc("/masque/tcp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if p := r.Header.Get(":protocol"); p != "" && p != strm.H2ConnectStreamProto {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		host := server.TCPConnectHost{
			Options: option.MasqueEndpointOptions{AllowPrivateTargets: true},
			Dialer:  net.Dialer{Timeout: 8 * time.Second},
			Authorize: func(*http.Request) bool {
				return true
			},
			AuthorityMatches: func(_, _ string, _ bool) bool { return true },
		}
		server.HandleTCPConnectRequest(host, w, r, tcpTemplate, true)
	})

	h3TLS := masque.InProcessH3TestTLS(t)
	h3TLS = h3TLS.Clone()
	h3TLS.NextProtos = []string{http3.NextProtoH3}
	collateralTLS := masque.InProcessH3TestTLS(t)
	collateralTLS = collateralTLS.Clone()
	collateralTLS.NextProtos = []string{"h2", "http/1.1"}

	stack, err := server.LaunchMasqueStack(server.LaunchMasqueStackConfig{
		Handler:       mux,
		ListenHost:    "127.0.0.1",
		ListenPort:    0,
		HTTP3TLS:      h3TLS,
		CollateralTLS: collateralTLS,
		ValidateUDP:   func(net.PacketConn) error { return nil },
	})
	if err != nil {
		t.Fatalf("LaunchMasqueStack: %v", err)
	}
	if stack == nil || stack.H3Server == nil || stack.PacketConn == nil {
		t.Fatal("expected HTTP/3 listener on LaunchMasqueStack")
	}
	t.Cleanup(func() {
		if shutErr := server.ShutdownMasqueEndpoint(server.ShutdownMasqueEndpointConfig{
			Stack:           stack,
			ShutdownTimeout: prodStackTestShutdownTimeout,
		}); shutErr != nil {
			t.Errorf("shutdown LaunchMasqueStack: %v", shutErr)
		}
	})

	udpAddr, ok := stack.PacketConn.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr == nil {
		t.Fatalf("unexpected UDP listener addr: %T", stack.PacketConn.LocalAddr())
	}
	port := udpAddr.Port
	rawTpl := fmt.Sprintf("https://127.0.0.1:%d/masque/tcp/{target_host}/{target_port}", port)
	var tplErr error
	tcpTemplate, tplErr = uritemplate.New(rawTpl)
	if tplErr != nil {
		t.Fatalf("tcp template: %v", tplErr)
	}
	time.Sleep(30 * time.Millisecond)
	return port
}

func startLaunchMasqueStackH2ConnectStreamServer(t *testing.T) int {
	t.Helper()
	var tcpTemplate *uritemplate.Template
	mux := http.NewServeMux()
	mux.HandleFunc("/masque/tcp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if p := r.Header.Get(":protocol"); p != "" && p != strm.H2ConnectStreamProto {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		host := server.TCPConnectHost{
			Options: option.MasqueEndpointOptions{AllowPrivateTargets: true},
			Dialer:  net.Dialer{Timeout: 8 * time.Second},
			Authorize: func(*http.Request) bool {
				return true
			},
			AuthorityMatches: func(_, _ string, _ bool) bool { return true },
		}
		server.HandleTCPConnectRequest(host, w, r, tcpTemplate, true)
	})

	h3TLS := masque.InProcessH3TestTLS(t)
	h3TLS = h3TLS.Clone()
	h3TLS.NextProtos = []string{http3.NextProtoH3}
	collateralTLS := masque.InProcessH3TestTLS(t)
	collateralTLS = collateralTLS.Clone()
	collateralTLS.NextProtos = []string{"h2", "http/1.1"}

	stack, err := server.LaunchMasqueStack(server.LaunchMasqueStackConfig{
		Handler:       mux,
		ListenHost:    "127.0.0.1",
		ListenPort:    0,
		HTTP3TLS:      h3TLS,
		CollateralTLS: collateralTLS,
		ValidateUDP:   func(net.PacketConn) error { return nil },
	})
	if err != nil {
		t.Fatalf("LaunchMasqueStack: %v", err)
	}
	if stack == nil || stack.HTTP2Server == nil || stack.TCPTLSListener == nil {
		t.Fatal("expected HTTP/2 collateral listener on LaunchMasqueStack")
	}
	t.Cleanup(func() {
		if shutErr := server.ShutdownMasqueEndpoint(server.ShutdownMasqueEndpointConfig{
			Stack:           stack,
			ShutdownTimeout: prodStackTestShutdownTimeout,
		}); shutErr != nil {
			t.Errorf("shutdown LaunchMasqueStack: %v", shutErr)
		}
	})

	tcpAddr, ok := stack.TCPTLSListener.Addr().(*net.TCPAddr)
	if !ok || tcpAddr == nil {
		t.Fatalf("unexpected TCP listener addr: %T", stack.TCPTLSListener.Addr())
	}
	port := tcpAddr.Port
	rawTpl := fmt.Sprintf("https://127.0.0.1:%d/masque/tcp/{target_host}/{target_port}", port)
	tcpTemplate, err = uritemplate.New(rawTpl)
	if err != nil {
		t.Fatalf("tcp template: %v", err)
	}
	time.Sleep(30 * time.Millisecond)
	return port
}

func runH3ProdStackSocksFakeIperfNoPulse(t *testing.T, proxyPort int, targetPort uint16, minBytes int64) int64 {
	t.Helper()
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)
	conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(h3DockerSynthStallWatchdog + 2*time.Second)); err != nil {
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
		t.Fatalf("fake iperf download short: %d want >= %d (docker iperf -R stall)", n, minBytes)
	}
	return n
}

func runH3ProdStackRealIperf3UploadFirst(t *testing.T, proxyPort int, targetPort uint16, minBytes int64) int64 {
	t.Helper()
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)
	conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(h3DockerSynthStallWatchdog + 2*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	cookie := masque.ExportTestIperf3ClientCookie()
	params := masque.ExportTestIperf3ClientParamsJSON(cookie)

	if _, err := conn.Write(cookie); err != nil {
		t.Fatalf("write iperf3 cookie: %v", err)
	}
	if _, err := conn.Write(params); err != nil {
		t.Fatalf("write iperf3 params: %v", err)
	}

	var dst bytes.Buffer
	n, err := io.Copy(&dst, conn)
	if err != nil && n == 0 {
		t.Fatalf("real iperf3 prod stack: %v", err)
	}
	if n < minBytes {
		t.Fatalf("real iperf3 prod stack short: %d want >= %d", n, minBytes)
	}
	return n
}

// TestGATEDockerH3SynthRealIperf3UploadFirst (GATE-DOCKER-H3-REAL) — real iperf3 upload-first cookie
// through prod LaunchMasqueStack + SOCKS/CM (not fake iperf3\\r\\n banner).
func TestGATEDockerH3SynthRealIperf3UploadFirst(t *testing.T) {
	targetPort := masque.ExportStartRealIperf3UploadFirstTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	n := runH3ProdStackRealIperf3UploadFirst(t, proxyPort, targetPort, h3ProdStackFakeIperfMinBytes)
	t.Logf("GATE-DOCKER-H3 real iperf3 upload-first: %d bytes", n)
	if n < h3ProdStackFakeIperfMinBytes {
		t.Fatalf("GATE-DOCKER-H3-REAL short read: %d want >= %d", n, h3ProdStackFakeIperfMinBytes)
	}
}

// TestGATEDockerH3SynthFakeIperfNoPulse (GATE-DOCKER-H3-SYNTH) — docker download-first iperf -R
// through full prod stack (LaunchMasqueStack + SOCKS/CM). WriteTo-only GATE-H3-SYNTH does not cover this.
func TestGATEDockerH3SynthFakeIperfNoPulse(t *testing.T) {
	targetPort := masque.ExportStartH2FakeIperfDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	n := runH3ProdStackSocksFakeIperfNoPulse(t, proxyPort, targetPort, h3ProdStackFakeIperfMinBytes)
	t.Logf("GATE-DOCKER-H3 fake iperf: %d bytes (handshake+bulk, no stall)", n)
	if n < h3ProdStackFakeIperfMinBytes {
		t.Fatalf("GATE-DOCKER-H3 short read: %d want >= %d", n, h3ProdStackFakeIperfMinBytes)
	}
}

// TestGATEDockerH3SynthIperfReverseWriteToMbps — prod stack iperf -R WriteTo; AGENTS KPI ≥1000 Mbit/s.
func TestGATEDockerH3SynthIperfReverseWriteToMbps(t *testing.T) {
	minMbps := masque.ExportConnectStreamSynthProdMinMbps
	targetPort := masque.ExportStartH2FakeIperfStreamingDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)
	conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(masque.ExportConnectStreamSynthProdBenchDuration + 8*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	banner := make([]byte, 8)
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("read iperf banner: %v", err)
	}
	if _, err := conn.Write([]byte("FAKEIPERF")); err != nil {
		t.Fatalf("write fake iperf params: %v", err)
	}
	n, mbps, err := masque.ExportMeasureTCPDownloadWriteToMbps(conn, masque.ExportConnectStreamSynthProdBenchDuration)
	if err != nil && n == 0 {
		t.Fatalf("GATE-DOCKER-H3 WriteTo: %v", err)
	}
	t.Logf("GATE-DOCKER-H3 iperf reverse WriteTo: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < minMbps {
		t.Fatalf("GATE-DOCKER-H3 iperf reverse %.1f < %.0f Mbit/s (AGENTS KPI)", mbps, minMbps)
	}
}

// TestGATEDockerLiveMasqueServerIperfReverseWriteToMbps isolates docker masque-server-core vs synth client.
// Run inside masque-backend: DOCKER_LIVE_SERVER=1 DOCKER_TEST_TARGET_HOST=<this container IP> go test -run TestGATEDockerLiveMasqueServerIperfReverseWriteToMbps
func TestGATEDockerLiveMasqueServerIperfReverseWriteToMbps(t *testing.T) {
	minMbps := masque.ExportConnectStreamSynthProdMinMbps
	targetHost := strings.TrimSpace(os.Getenv("DOCKER_TEST_TARGET_HOST"))
	if targetHost == "" {
		t.Skip("set DOCKER_TEST_TARGET_HOST to this container IP on masque-backend")
	}
	session := masque.ExportNewConnectStreamH3DockerLiveSession(t)
	targetPort := masque.ExportStartH2FakeIperfStreamingDownloadTargetOn(t, "0.0.0.0")
	socksPort := masque.ExportStartH3ConnectStreamSocksRouterWithSession(t, session)
	conn := masque.ExportSocksTCPDialHost(t, socksPort, targetHost, targetPort)
	if err := conn.SetDeadline(time.Now().Add(masque.ExportConnectStreamSynthProdBenchDuration + 8*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	banner := make([]byte, 8)
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("read iperf banner: %v", err)
	}
	if _, err := conn.Write([]byte("FAKEIPERF")); err != nil {
		t.Fatalf("write fake iperf params: %v", err)
	}
	n, mbps, err := masque.ExportMeasureTCPDownloadWriteToMbps(conn, masque.ExportConnectStreamSynthProdBenchDuration)
	if err != nil && n == 0 {
		t.Fatalf("docker live server WriteTo: %v", err)
	}
	t.Logf("docker live server iperf reverse WriteTo: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < minMbps {
		t.Fatalf("docker live server %.1f < %.0f Mbit/s (AGENTS KPI)", mbps, minMbps)
	}
}

// TestGATEDockerH3SynthFakeIperfH2Parity — H2 negative control on same docker-shaped gate.
func TestGATEDockerH3SynthFakeIperfH2Parity(t *testing.T) {
	targetPort := masque.ExportStartH2FakeIperfConcurrentControlTarget(t)
	proxyPort := startLaunchMasqueStackH2ConnectStreamServer(t)
	socksPort := masque.ExportStartH2ConnectStreamSocksRouter(t, proxyPort)
	conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(h3DockerSynthStallWatchdog)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	banner := make([]byte, 8)
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("H2 read banner: %v", err)
	}
	if _, err := conn.Write([]byte("FAKEIPERF")); err != nil {
		t.Fatalf("H2 write params: %v", err)
	}
	n, mbps, err := masque.ExportMeasureTCPDownloadCopyMbps(conn, h3DockerSynthDownloadBench)
	if err != nil && n == 0 {
		t.Fatalf("H2 docker gate: %v", err)
	}
	t.Logf("GATE-DOCKER-H2 parity: %.1f Mbit/s (%d bytes)", mbps, n)
	if n < h3ProdStackFakeIperfMinBytes {
		t.Fatalf("H2 parity bytes=%d want >= %d", n, h3ProdStackFakeIperfMinBytes)
	}
	if mbps <= masque.ExportConnectStreamVPSKPITargetDown {
		t.Fatalf("H2 parity %.1f Mbit/s (want > %.0f)", mbps, masque.ExportConnectStreamVPSKPITargetDown)
	}
}

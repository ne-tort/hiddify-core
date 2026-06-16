package masque_test

// Prod-stack synth: LaunchMasqueStack (docker server) + CoreClientFactory H3 + SOCKS/CM.

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque/server"
	"github.com/sagernet/sing-box/transport/masque"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	"github.com/yosida95/uritemplate/v3"
)

const (
	h3ProdStackFakeIperfMinBytes   = 32 * 1024
	h3DockerSynthStallWatchdog     = 10 * time.Second
	h3DockerSynthDownloadBench     = 2 * time.Second
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
		if shutErr := server.ShutdownMasqueEndpoint(server.ShutdownMasqueEndpointConfig{Stack: stack}); shutErr != nil {
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

func runH3ProdStackFakeIperfDownloadMbps(t *testing.T, proxyPort int, targetPort uint16, duration time.Duration) (int64, float64, error) {
	t.Helper()
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)
	conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(duration + h3DockerSynthStallWatchdog)); err != nil {
		return 0, 0, err
	}

	banner := make([]byte, 8)
	if _, err := io.ReadFull(conn, banner); err != nil {
		return 0, 0, err
	}
	if _, err := conn.Write([]byte("FAKEIPERF")); err != nil {
		return 0, 0, err
	}
	return masque.ExportMeasureTCPDownloadCopyMbps(conn, duration)
}

// TestLaunchMasqueStackH3ConnectStreamFakeIperfNoPulse (H3-Docker) — prod LaunchMasqueStack + SOCKS/CM
// with docker iperf -R handshake (Read banner, Write params, io.Copy bulk) and no synthetic upload pulse.
func TestLaunchMasqueStackH3ConnectStreamFakeIperfNoPulse(t *testing.T) {
	targetPort := masque.ExportStartH2FakeIperfDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	n := runH3ProdStackSocksFakeIperfNoPulse(t, proxyPort, targetPort, h3ProdStackFakeIperfMinBytes)
	t.Logf("LaunchMasqueStack H3 fake iperf no-pulse: %d bytes", n)
}

// TestLaunchMasqueStackH3WriteToOnlyIperfBanner (H3-Docker) — iperf -R may start WriteTo download
// before reading banner; must not block >9s waiting for server bulk (docker hang shape).
func TestLaunchMasqueStackH3WriteToOnlyIperfBanner(t *testing.T) {
	targetPort := masque.ExportStartH2FakeIperfDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)

	conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(h3DockerSynthStallWatchdog)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, _, err := masque.ExportMeasureTCPDownloadWriteToMbps(conn, h3DockerSynthDownloadBench)
		done <- result{n: n, err: err}
	}()

	select {
	case r := <-done:
		if r.err != nil && r.n < 8 {
			t.Fatalf("WriteTo-only iperf banner: %v (n=%d)", r.err, r.n)
		}
		if r.n < 8 {
			t.Fatalf("WriteTo-only got %d bytes want >= 8 (iperf3\\r\\n banner)", r.n)
		}
		t.Logf("WriteTo-only iperf banner path: %d bytes", r.n)
	case <-time.After(h3DockerSynthStallWatchdog - time.Second):
		t.Fatal("WriteTo-only download blocked >9s waiting for iperf banner (docker hang shape)")
	}
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

// TestLaunchMasqueStackH3ConcurrentControlDuringWriteTo (H3-T6-05) — prod stack + CM WriteTo download
// with concurrent non-zero upload control (no benchWindowedBidiLink wrap).
func TestLaunchMasqueStackH3ConcurrentControlDuringWriteTo(t *testing.T) {
	targetPort := masque.ExportStartH2FakeIperfConcurrentControlTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)
	conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
	conn = masque.ExportWrapBenchWindowedBidiLinkStrictH3(conn)
	if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

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
		n, _, err := masque.ExportMeasureTCPDownloadWriteToMbps(conn, masque.ExportH3HonestGateDuration)
		done <- result{n: n, err: err}
	}()

	select {
	case r := <-done:
		if r.err != nil && r.n == 0 {
			t.Fatalf("concurrent control WriteTo: %v", r.err)
		}
		t.Logf("LaunchMasqueStack H3 concurrent control WriteTo: %d bytes", r.n)
		if r.n < masque.ExportH3HonestGateMinBytes {
			t.Fatalf("concurrent control download short: %d want >= %d (H3 bidi FC stall)", r.n, masque.ExportH3HonestGateMinBytes)
		}
	case <-time.After(masque.ExportH3HonestGateDuration + 5*time.Second):
		t.Fatal("concurrent control WriteTo blocked past deadline (H3 bidi FC stall)")
	}
}

// TestLaunchMasqueStackH3ConnectStreamDownloadKPI (H3-L6 KPI) — prod LaunchMasqueStack + SOCKS/CM.
// Threshold: GATE-H3-SYNTH (>= ExportConnectStreamSynthProdMinMbps).
func TestLaunchMasqueStackH3ConnectStreamDownloadKPI(t *testing.T) {
	targetPort := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)

	conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, ok := masque.ExportWriterTo(conn); !ok {
		t.Fatal("SOCKS masque conn lacks io.WriterTo")
	}
	n, mbps, err := masque.ExportMeasureTCPDownloadWriteToMbps(conn, masque.ExportConnectStreamSynthProdBenchDuration)
	if err != nil && n == 0 {
		t.Fatalf("prod stack WriteTo: %v", err)
	}
	t.Logf("LaunchMasqueStack H3 download KPI: %.1f Mbit/s (%d bytes)", mbps, n)
	if n < masque.ExportLocalizeBenchMinBytes {
		t.Fatalf("bytes=%d want >= %d", n, masque.ExportLocalizeBenchMinBytes)
	}
	if mbps < masque.ExportConnectStreamSynthProdMinMbps {
		t.Fatalf("%s", masque.ExportSynthKPIDiagnostic("[H3-L0 prod stack]", "tcp_down WriteTo", mbps,
			masque.ExportConnectStreamSynthProdMinMbps, "LaunchMasqueStack H3 + SOCKS/CM; gap vs H2 anchor"))
	}
}

// TestLaunchMasqueStackH3ConnectStreamDownloadKPIWindowedNoPulse (H3-B0) — prod stack + strict H3 RTT wrap.
func TestLaunchMasqueStackH3ConnectStreamDownloadKPIWindowedNoPulse(t *testing.T) {
	targetPort := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)

	conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
	conn = masque.ExportWrapBenchWindowedBidiLinkStrictH3L256(conn)
	if err := conn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	n, mbps, err := masque.ExportMeasureTCPDownloadWriteToMbps(conn, masque.ExportLocalizeBenchDuration)
	if err != nil && n == 0 {
		t.Fatalf("prod stack windowed WriteTo: %v", err)
	}
	t.Logf("LaunchMasqueStack H3 windowed no-pulse: %.1f Mbit/s (%d bytes)", mbps, n)
	if n < masque.ExportLocalizeBenchMinBytes {
		t.Fatalf("bytes=%d want >= %d", n, masque.ExportLocalizeBenchMinBytes)
	}
	if mbps <= masque.ExportConnectStreamVPSKPITargetDown {
		t.Fatalf("prod stack windowed download: %.1f Mbit/s (want > %.0f KPI)", mbps, masque.ExportConnectStreamVPSKPITargetDown)
	}
}

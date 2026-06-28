package inttest_test

// Prod-stack synth: LaunchMasqueStack (docker server) + CoreClientFactory H2 + SOCKS/CM.

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
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

const h2ProdStackFakeIperfMinBytes = 32 * 1024

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
		if shutErr := server.ShutdownMasqueEndpoint(server.ShutdownMasqueEndpointConfig{Stack: stack}); shutErr != nil {
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

func runH2ProdStackSocksFakeIperfNoPulse(t *testing.T, proxyPort int, targetPort uint16, minBytes int64) int64 {
	t.Helper()
	socksPort := masque.InttestStartH2ConnectStreamSocksRouter(t, proxyPort)
	conn := masque.InttestSocksTCPDial(t, socksPort, targetPort)
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
	return n
}

// TestLaunchMasqueStackH2ConnectStreamFakeIperfNoPulse (H2-L1) — prod server stack + SOCKS/CM client.
func TestLaunchMasqueStackH2ConnectStreamFakeIperfNoPulse(t *testing.T) {
	targetPort := masque.InttestStartH2FakeIperfDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH2ConnectStreamServer(t)
	n := runH2ProdStackSocksFakeIperfNoPulse(t, proxyPort, targetPort, h2ProdStackFakeIperfMinBytes)
	t.Logf("LaunchMasqueStack H2 fake iperf no-pulse: %d bytes", n)
}

// TestLaunchMasqueStackH2WriteToOnlyIperfBanner (H2-Docker) — iperf -R shape: CM writer_to download
// without client Read of banner first (measureTCPDownloadWriteToMbps, same as docker iperf -R).
func TestLaunchMasqueStackH2WriteToOnlyIperfBanner(t *testing.T) {
	targetPort := masque.InttestStartH2FakeIperfDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH2ConnectStreamServer(t)
	socksPort := masque.InttestStartH2ConnectStreamSocksRouter(t, proxyPort)

	conn := masque.InttestSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, _, err := masque.InttestMeasureTCPDownloadWriteToMbps(conn, 2*time.Second)
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
	case <-time.After(9 * time.Second):
		t.Fatal("WriteTo-only download blocked >9s waiting for iperf banner (docker hang shape)")
	}
}

// TestLaunchMasqueStackH2ConnectStreamDownloadKPI (H2-L1 KPI) — prod LaunchMasqueStack + SOCKS/CM.
// Threshold: GATE-H2-SYNTH (>= ExportConnectStreamSynthProdMinMbps); weak >21 is K-S1 floor only.
func TestLaunchMasqueStackH2ConnectStreamDownloadKPI(t *testing.T) {
	targetPort := masque.InttestStartH2ProdStackBulkDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH2ConnectStreamServer(t)
	socksPort := masque.InttestStartH2ConnectStreamSocksRouter(t, proxyPort)

	conn := masque.InttestSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, ok := masque.InttestWriterTo(conn); !ok {
		t.Fatal("SOCKS masque conn lacks io.WriterTo")
	}
	n, mbps, err := masque.InttestMeasureTCPDownloadWriteToMbps(conn, masque.InttestConnectStreamSynthProdBenchDuration())
	if err != nil && n == 0 {
		t.Fatalf("prod stack WriteTo: %v", err)
	}
	t.Logf("LaunchMasqueStack H2 download KPI: %.1f Mbit/s (%d bytes)", mbps, n)
	if n < masque.InttestLocalizeBenchMinBytes() {
		t.Fatalf("bytes=%d want >= %d", n, masque.InttestLocalizeBenchMinBytes())
	}
	if mbps < masque.ExportConnectStreamSynthProdMinMbps {
		t.Fatalf("%s", masque.InttestSynthKPIDiagnostic("[H2-L0 prod stack]", "tcp_down WriteTo", mbps,
			masque.ExportConnectStreamSynthProdMinMbps, "LaunchMasqueStack H2 + SOCKS/CM"))
	}
}

// TestLaunchMasqueStackH2ConnectStreamDownloadKPIWindowedNoPulse (H2-B0) — prod stack + field RTT wrap + P1c default.
func TestLaunchMasqueStackH2ConnectStreamDownloadKPIWindowedNoPulse(t *testing.T) {
	targetPort := masque.InttestStartH2ProdStackBulkDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH2ConnectStreamServer(t)
	socksPort := masque.InttestStartH2ConnectStreamSocksRouter(t, proxyPort)

	conn := masque.InttestSocksTCPDial(t, socksPort, targetPort)
	conn = masque.InttestWrapBenchWindowedBidiLinkH2Prod(conn)
	if err := conn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	wt, ok := masque.InttestWriterTo(conn)
	if !ok {
		t.Fatal("SOCKS masque conn lacks io.WriterTo")
	}
	_ = wt
	n, mbps, err := masque.InttestMeasureTCPDownloadWriteToMbps(conn, masque.InttestLocalizeBenchDuration())
	if err != nil && n == 0 {
		t.Fatalf("prod stack windowed WriteTo: %v", err)
	}
	t.Logf("LaunchMasqueStack H2 windowed no-pulse: %.1f Mbit/s (%d bytes)", mbps, n)
	if n < masque.InttestLocalizeBenchMinBytes() {
		t.Fatalf("bytes=%d want >= %d", n, masque.InttestLocalizeBenchMinBytes())
	}
	if mbps <= masque.InttestConnectStreamVPSKPITargetDown() {
		t.Fatalf("prod stack windowed download: %.1f Mbit/s (want > %.0f KPI)", mbps, masque.InttestConnectStreamVPSKPITargetDown())
	}
}

// TestLaunchMasqueStackH2ConnectStreamDownloadKPINetem (H-B) — prod stack + field RTT model (windowed wrap, no synthetic TCP sleep).
func TestLaunchMasqueStackH2ConnectStreamDownloadKPINetem(t *testing.T) {
	targetPort := masque.InttestStartH2ProdStackBulkDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH2ConnectStreamServer(t)
	socksPort := masque.InttestStartH2ConnectStreamSocksRouter(t, proxyPort)

	conn := masque.InttestSocksTCPDial(t, socksPort, targetPort)
	conn = masque.InttestWrapBenchWindowedBidiLinkH2Prod(conn)
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	n, mbps, err := masque.InttestMeasureTCPDownloadWriteToMbps(conn, masque.InttestLocalizeBenchDuration())
	if err != nil && n == 0 {
		t.Fatalf("netem prod stack WriteTo: %v", err)
	}
	t.Logf("LaunchMasqueStack H2 netem download KPI: %.1f Mbit/s (%d bytes)", mbps, n)
	if n < masque.InttestLocalizeBenchMinBytes() {
		t.Fatalf("bytes=%d want >= %d", n, masque.InttestLocalizeBenchMinBytes())
	}
	if mbps <= masque.InttestConnectStreamVPSKPITargetDown() {
		t.Fatalf("netem prod stack download: %.1f Mbit/s (want > %.0f KPI)", mbps, masque.InttestConnectStreamVPSKPITargetDown())
	}
}

// TestLaunchMasqueStackH2ConnectStreamFakeIperfNoEager (H2-R5) — prod stack with
// MASQUE_H2_DOWNLOAD_EAGER_WINDOW=0 must still complete fake iperf handshake (no stall).
func TestLaunchMasqueStackH2ConnectStreamFakeIperfNoEager(t *testing.T) {
	t.Setenv("MASQUE_H2_DOWNLOAD_EAGER_WINDOW", "0")
	targetPort := masque.InttestStartH2FakeIperfDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH2ConnectStreamServer(t)
	n := runH2ProdStackSocksFakeIperfNoPulse(t, proxyPort, targetPort, h2ProdStackFakeIperfMinBytes)
	t.Logf("LaunchMasqueStack H2 fake iperf eager=0: %d bytes", n)
}

// TestCMRouteWriterToBranchViaSocks (H2-R6) — full SOCKS/CM E2E must select writer_to on masque leg.
func TestCMRouteWriterToBranchViaSocks(t *testing.T) {
	t.Setenv("MASQUE_TRACE_COPY", "1")
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w

	traceDone := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		traceDone <- buf.String()
	}()

	targetPort := masque.InttestStartH2FakeIperfDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH2ConnectStreamServer(t)
	socksPort := masque.InttestStartH2ConnectStreamSocksRouter(t, proxyPort)
	conn := masque.InttestSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	_, _, _ = masque.InttestMeasureTCPDownloadWriteToMbps(conn, 500*time.Millisecond)

	w.Close()
	os.Stderr = oldStderr
	trace := <-traceDone

	if !bytes.Contains([]byte(trace), []byte("branch=writer_to")) {
		t.Fatalf("CM trace missing writer_to branch:\n%s", trace)
	}
	if !bytes.Contains([]byte(trace), []byte("direction=download")) {
		t.Fatalf("CM trace missing download direction:\n%s", trace)
	}
	if !bytes.Contains([]byte(trace), []byte("source_marker=true")) {
		t.Fatalf("CM trace missing masque source_marker:\n%s", trace)
	}
	t.Logf("CM writer_to branch via SOCKS OK")
}

// TestLaunchMasqueStackH2ConcurrentControlDuringWriteTo (H2-T6-05) — prod stack + CM WriteTo download
// with concurrent non-zero upload control (no benchWindowedBidiLink wrap). Must exceed 32 KiB / 15 s.
func TestLaunchMasqueStackH2ConcurrentControlDuringWriteTo(t *testing.T) {
	targetPort := masque.InttestStartH2FakeIperfConcurrentControlTarget(t)
	proxyPort := startLaunchMasqueStackH2ConnectStreamServer(t)
	socksPort := masque.InttestStartH2ConnectStreamSocksRouter(t, proxyPort)
	conn := masque.InttestSocksTCPDial(t, socksPort, targetPort)
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
		n, _, err := masque.InttestMeasureTCPDownloadWriteToMbps(conn, masque.InttestH2HonestGateDuration())
		done <- result{n: n, err: err}
	}()

	select {
	case r := <-done:
		if r.err != nil && r.n == 0 {
			t.Fatalf("concurrent control WriteTo: %v", r.err)
		}
		t.Logf("LaunchMasqueStack H2 concurrent control WriteTo: %d bytes", r.n)
		if r.n < masque.InttestH2HonestGateMinBytes() {
			t.Fatalf("concurrent control download short: %d want >= %d (H2 bidi FC stall)", r.n, masque.InttestH2HonestGateMinBytes())
		}
	case <-time.After(masque.InttestH2HonestGateDuration() + 5*time.Second):
		t.Fatal("concurrent control WriteTo blocked past deadline (H2 bidi FC stall)")
	}
}

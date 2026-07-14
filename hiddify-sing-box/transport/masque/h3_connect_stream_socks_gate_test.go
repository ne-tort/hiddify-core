package masque

// GATE-H3 in-process SOCKS CONNECT-stream synth (KPI ≥1000 Mbit/s). Non-GATE → stream/inttest/.

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestGATEH3DownloadTargetDirectDialBanner — fake iperf target blocks after banner until params.
func TestGATEH3DownloadTargetDirectDialBanner(t *testing.T) {
	targetPort := startH2FakeIperfDownloadTarget(t)
	conn := dialH3ConnectStreamBench(t, int(targetPort))
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	banner := make([]byte, 8)
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("read iperf banner: %v", err)
	}
	if string(banner) != "iperf3\r\n" {
		t.Fatalf("banner: got %q", string(banner))
	}
}

// TestGATEH3DownloadTargetSocksBanner — same target through prod SOCKS/CM route.
func TestGATEH3DownloadTargetSocksBanner(t *testing.T) {
	targetPort := startH2FakeIperfDownloadTarget(t)
	proxyPort := startInProcessTCPConnectStreamRelayProxy(t)
	socksPort := startH3ConnectStreamSocksRouter(t, proxyPort)
	conn := socksTCPDial(t, socksPort, targetPort)
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	banner := make([]byte, 8)
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("read iperf banner: %v", err)
	}
	if string(banner) != "iperf3\r\n" {
		t.Fatalf("banner: got %q", string(banner))
	}
}

// TestGATEH3DownloadTargetSocksFakeIperfNoPulse mirrors stream/inttest fake iperf path.
func TestGATEH3DownloadTargetSocksFakeIperfNoPulse(t *testing.T) {
	targetPort := startH2FakeIperfDownloadTarget(t)
	proxyPort := startInProcessTCPConnectStreamRelayProxy(t)
	n := runH3SocksFakeIperfNoPulse(t, proxyPort, targetPort, int64(h2ConnectStreamSocksMinRead))
	t.Logf("fake iperf no-pulse: %d bytes", n)
}

// TestGATEH3IperfReverseHandshakeRouteMbps — prod iperf -R WriteTo (no RTT harness); AGENTS KPI ≥1000 Mbit/s.
func TestGATEH3IperfReverseHandshakeRouteMbps(t *testing.T) {
	dur := connectStreamSynthProdBenchDuration
	targetPort := startH2FakeIperfStreamingDownloadTarget(t)
	proxyPort := startInProcessTCPConnectStreamRelayProxy(t)
	socksPort := startH3ConnectStreamSocksRouter(t, proxyPort)
	conn := socksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(dur + 8*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	banner := make([]byte, 8)
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("read iperf banner: %v", err)
	}
	if string(banner) != "iperf3\r\n" {
		t.Fatalf("banner: got %q", string(banner))
	}
	if _, err := conn.Write([]byte("FAKEIPERF")); err != nil {
		t.Fatalf("write fake iperf params: %v", err)
	}
	n, mbps, err := measureTCPDownloadWriteToMbps(conn, dur)
	if err != nil && n == 0 {
		t.Fatalf("iperf reverse route WriteTo: %v", err)
	}
	t.Logf("iperf reverse route WriteTo: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < connectStreamSynthProdMinMbps {
		t.Fatalf("%s", synthKPIDiagnostic("[H3 iperf -R route]", "tcp_down WriteTo", mbps,
			connectStreamSynthProdMinMbps, "prod path without L256 harness"))
	}
}

// TestGATEH3TwinConnectStreamSharedQUICDownloadMbps — twin SOCKS on one QUIC; KPI ≥1000 Mbit/s.
func TestGATEH3TwinConnectStreamSharedQUICDownloadMbps(t *testing.T) {
	dur := connectStreamSynthProdBenchDuration
	targetPort := startH2FakeIperfStreamingDownloadTarget(t)
	proxyPort := startInProcessTCPConnectStreamRelayProxy(t)
	session, _ := newConnectStreamH3ProdSession(t, proxyPort)
	socksPort := startH3ConnectStreamSocksRouterWithSession(t, session)

	dialTwin := func() net.Conn {
		t.Helper()
		conn := socksTCPDial(t, socksPort, targetPort)
		if err := conn.SetDeadline(time.Now().Add(dur + 10*time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		return conn
	}
	connPrimary := dialTwin()
	connTwin := dialTwin()

	handshake := func(conn net.Conn) {
		t.Helper()
		banner := make([]byte, 8)
		if _, err := io.ReadFull(conn, banner); err != nil {
			t.Fatalf("read iperf banner: %v", err)
		}
		if _, err := conn.Write([]byte("FAKEIPERF")); err != nil {
			t.Fatalf("write fake iperf params: %v", err)
		}
	}
	handshake(connPrimary)

	twinDone := make(chan struct{})
	go func() {
		defer close(twinDone)
		handshake(connTwin)
		_, _ = io.Copy(io.Discard, connTwin)
	}()

	n, mbps, err := measureTCPDownloadWriteToMbps(connPrimary, dur)
	<-twinDone
	if err != nil && n == 0 {
		t.Fatalf("twin CONNECT download: %v", err)
	}
	t.Logf("twin CONNECT shared QUIC download: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < connectStreamSynthTwinMinMbps {
		t.Fatalf("%s", synthKPIDiagnostic("[H3 twin CONNECT]", "tcp_down WriteTo", mbps,
			connectStreamSynthTwinMinMbps, "shared QUIC iperf -R"))
	}
}

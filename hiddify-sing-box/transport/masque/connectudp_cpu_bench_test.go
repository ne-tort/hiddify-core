package masque

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

func connectUDPCPUBenchPayload() []byte {
	payload := make([]byte, connectudp.DefaultBenchUDPPayloadLen)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	return payload
}

func setupL0CPUBench(t testing.TB) (net.PacketConn, net.Addr, []byte) {
	t.Helper()
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, sink.LocalAddr(), connectUDPCPUBenchPayload()
}

func setupH3UploadCPUBench(t testing.TB) (net.PacketConn, *net.UDPAddr, []byte) {
	t.Helper()
	sink, _ := runUDPSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})
	target := net.JoinHostPort(sinkAddr.IP.String(), strconv.Itoa(sinkAddr.Port))
	pkt := dialH3ConnectUDPDirect(t, proxyPort, target)
	return pkt, sinkAddr, connectUDPCPUBenchPayload()
}

func setupH2UploadCPUBench(t testing.TB) (net.PacketConn, *net.UDPAddr, []byte) {
	t.Helper()
	sink, _ := runUDPSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newConnectUDPProdProfileH2SessionWithLinkTB(t, proxyPort, instantH2Link{})
	target := net.JoinHostPort(sinkAddr.IP.String(), strconv.Itoa(sinkAddr.Port))
	pkt := dialConnectUDPH2ViaSession(t, session, waitCtx, target)
	return pkt, sinkAddr, connectUDPCPUBenchPayload()
}

func setupH3DownloadCPUBench(t testing.TB) (net.PacketConn, []byte) {
	t.Helper()
	fountain := startUDPFountain(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	pkt, _ := newConnectUDPH3ProdListenPacket(t, M.Socksaddr{
		Addr: netip.MustParseAddr(fountainAddr.IP.String()),
		Port: uint16(fountainAddr.Port),
	})
	if err := primeFountainReceiveBenchErr(t, pkt, fountainAddr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, connectudp.DefaultBenchUDPPayloadLen+64)
	drainPacketConnBuffered(t, pkt, buf, 200*time.Millisecond)
	return pkt, buf
}

// drainPacketConnBuffered discards queued datagrams so CPU sample hits live ReadFrom+QUIC path.
func drainPacketConnBuffered(tb testing.TB, pkt net.PacketConn, buf []byte, dur time.Duration) {
	tb.Helper()
	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		_ = pkt.SetReadDeadline(time.Now().Add(2 * time.Millisecond))
		_, _, _ = pkt.ReadFrom(buf)
	}
	_ = pkt.SetReadDeadline(time.Time{})
}

func TestGATEConnectUDPCPUBudgetL0Upload(t *testing.T) {
	pkt, addr, payload := setupL0CPUBench(t)
	runCPUBudgetGate(t, cpuSiteL0Upload, connectUDPL0UploadMaxNsPerB, connectUDPCPUBenchGateWall, func() int64 {
		return benchConnectUDPCPUUploadN(t, pkt, addr, payload, connectUDPCPUBenchIterBytes)
	})
}

func TestGATEConnectUDPCPUBudgetH3Upload(t *testing.T) {
	pkt, addr, payload := setupH3UploadCPUBench(t)
	runCPUBudgetGate(t, cpuSiteH3Upload, connectUDPL1H3UploadMaxNsPerB, connectUDPCPUBenchGateWall, func() int64 {
		return benchConnectUDPCPUUploadN(t, pkt, addr, payload, connectUDPCPUBenchIterBytes)
	})
}

func TestGATEConnectUDPCPUBudgetH2Upload(t *testing.T) {
	pkt, addr, payload := setupH2UploadCPUBench(t)
	runCPUBudgetGate(t, cpuSiteH2Upload, connectUDPL1H2UploadMaxNsPerB, connectUDPCPUBenchGateWall, func() int64 {
		return benchConnectUDPCPUUploadN(t, pkt, addr, payload, connectUDPCPUBenchIterBytes)
	})
}

func TestGATEConnectUDPCPUBudgetH3Download(t *testing.T) {
	pkt, buf := setupH3DownloadCPUBench(t)
	runCPUBudgetGate(t, cpuSiteH3Download, connectUDPL1H3DownloadMaxNsPerB, connectUDPCPUBenchGateWall, func() int64 {
		return benchConnectUDPCPUReceiveN(t, pkt, buf, connectUDPCPUBenchIterBytes)
	})
}

// TestLocalizeConnectUDPCPUBudgetMatrix logs all CPU budget sites; hard fail if matrix wall exceeded.
func TestLocalizeConnectUDPCPUBudgetMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	matrixStart := time.Now()
	type siteSpec struct {
		name      string
		maxNsPerB float64
		setup     func(testing.TB) func() int64
	}
	sites := []siteSpec{
		{
			cpuSiteL0Upload, connectUDPL0UploadMaxNsPerB,
			func(tb testing.TB) func() int64 {
				pkt, addr, payload := setupL0CPUBench(tb)
				return func() int64 {
					return benchConnectUDPCPUUploadN(tb, pkt, addr, payload, connectUDPCPUBenchIterBytes)
				}
			},
		},
		{
			cpuSiteH3Upload, connectUDPL1H3UploadMaxNsPerB,
			func(tb testing.TB) func() int64 {
				pkt, addr, payload := setupH3UploadCPUBench(tb)
				return func() int64 {
					return benchConnectUDPCPUUploadN(tb, pkt, addr, payload, connectUDPCPUBenchIterBytes)
				}
			},
		},
		{
			cpuSiteH2Upload, connectUDPL1H2UploadMaxNsPerB,
			func(tb testing.TB) func() int64 {
				pkt, addr, payload := setupH2UploadCPUBench(tb)
				return func() int64 {
					return benchConnectUDPCPUUploadN(tb, pkt, addr, payload, connectUDPCPUBenchIterBytes)
				}
			},
		},
		{
			cpuSiteH3Download, connectUDPL1H3DownloadMaxNsPerB,
			func(tb testing.TB) func() int64 {
				pkt, buf := setupH3DownloadCPUBench(tb)
				return func() int64 {
					return benchConnectUDPCPUReceiveN(tb, pkt, buf, connectUDPCPUBenchIterBytes)
				}
			},
		},
	}
	for _, s := range sites {
		if elapsed := time.Since(matrixStart); elapsed > connectUDPCPUBudgetMatrixWall {
			t.Fatalf("CPU matrix hung: elapsed=%v before site %s (max %v)", elapsed.Round(time.Millisecond), s.name, connectUDPCPUBudgetMatrixWall)
		}
		t.Run(s.name, func(t *testing.T) {
			iter := s.setup(t)
			nsPerB, wall := measureCPUBudgetGate(t, s.name, connectUDPCPUBenchGateWall, connectUDPCPUBenchGateBytes, iter)
			logCPUBudgetLine(t, s.name, cpuSiteCodeRef[s.name], nsPerB, s.maxNsPerB, wall)
			if nsPerB > s.maxNsPerB {
				t.Logf("OPEN: %s", synthKPIDiagnostic(s.name, "cpu_ns_per_b", nsPerB, s.maxNsPerB,
					"CPU budget localize — not hard GATE unless regression"))
			}
		})
	}
	t.Logf("CPU matrix total wall=%v", time.Since(matrixStart).Round(time.Millisecond))
}

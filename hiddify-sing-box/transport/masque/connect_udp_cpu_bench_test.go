package masque

// CONNECT-UDP CPU budget gates: L0 raw UDP vs L1 full MASQUE upload/download (H3/H2 instant link).

import (
	"net"
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

type connectUDPCPULegResult struct {
	layer    string
	leg      string
	nsPerB   float64
	maxNsPerB float64
}

func runConnectUDPL0UploadOnce(nbytes int64) (int64, error) {
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return 0, err
	}
	defer sink.Close()
	conn, err := net.DialUDP("udp", nil, sink.LocalAddr().(*net.UDPAddr))
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	payload := make([]byte, connectudp.DefaultBenchUDPPayloadLen)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	var sent int64
	for sent < nbytes {
		n, err := conn.Write(payload)
		if err != nil {
			return sent, err
		}
		sent += int64(n)
	}
	return sent, nil
}

func measureConnectUDPCPUBudget(t *testing.T, layer, leg string, maxNsPerB float64, run func(int64) (int64, error)) connectUDPCPULegResult {
	t.Helper()
	result := testing.Benchmark(func(b *testing.B) {
		b.SetBytes(masqueCPUBenchBytes)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			n, err := run(masqueCPUBenchBytes)
			if err != nil {
				b.Fatal(err)
			}
			if n < masqueCPUBenchBytes {
				b.Fatalf("short %s: %d", leg, n)
			}
		}
	})
	if result.N == 0 {
		t.Fatal("benchmark produced zero iterations")
	}
	nsPerByte := float64(result.NsPerOp()) / float64(masqueCPUBenchBytes)
	if nsPerByte > maxNsPerB {
		t.Fatalf("connect-udp %s %s CPU budget: %.1f ns/B > %.0f ns/B (implied ceiling %.0f Mbit/s)",
			layer, leg, nsPerByte, maxNsPerB, synthCPUMbpsCeiling(nsPerByte))
	}
	t.Logf("connect-udp %s %s CPU: %.1f ns/B (ceiling %.0f; implied %.0f Mbit/s)",
		layer, leg, nsPerByte, maxNsPerB, synthCPUMbpsCeiling(nsPerByte))
	return connectUDPCPULegResult{layer: layer, leg: leg, nsPerB: nsPerByte, maxNsPerB: maxNsPerB}
}

func logConnectUDPCPUPaired(t *testing.T, stack string, upMbps, downMbps float64, up, down connectUDPCPULegResult) {
	t.Helper()
	upCeil := synthCPUMbpsCeiling(up.nsPerB)
	downCeil := synthCPUMbpsCeiling(down.nsPerB)
	ratio := down.nsPerB / up.nsPerB
	if up.nsPerB > 0 && down.nsPerB >= up.nsPerB {
		t.Logf("connect-udp %s paired CPU: up %.1f ns/B down %.1f ns/B (down/up %.2fx); Mbps up %.1f down %.1f; implied ceiling up %.0f down %.0f",
			stack, up.nsPerB, down.nsPerB, ratio, upMbps, downMbps, upCeil, downCeil)
	} else if up.nsPerB > 0 {
		t.Logf("connect-udp %s paired CPU: up %.1f ns/B down %.1f ns/B (up/down %.2fx); Mbps up %.1f down %.1f; implied ceiling up %.0f down %.0f",
			stack, up.nsPerB, down.nsPerB, up.nsPerB/down.nsPerB, upMbps, downMbps, upCeil, downCeil)
	}
}

// BenchmarkConnectUDPUploadLayer profiles per-layer CONNECT-UDP upload CPU (L0 / L1-H3 / L1-H2).
func BenchmarkConnectUDPUploadLayer(b *testing.B) {
	b.Run("L0", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(masqueCPUBenchBytes)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			n, err := runConnectUDPL0UploadOnce(masqueCPUBenchBytes)
			if err != nil {
				b.Fatal(err)
			}
			if n < masqueCPUBenchBytes {
				b.Fatalf("short upload: %d want %d", n, masqueCPUBenchBytes)
			}
		}
	})
	b.Run("L1-H3-up", func(b *testing.B) {
		h := startConnectUDPProdH3UploadHandle(b)
		defer h.close()
		b.ReportAllocs()
		b.SetBytes(masqueCPUBenchBytes)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			n, err := h.uploadOnce(masqueCPUBenchBytes)
			if err != nil {
				b.Fatal(err)
			}
			if n < masqueCPUBenchBytes {
				b.Fatalf("short upload: %d want %d", n, masqueCPUBenchBytes)
			}
		}
	})
	b.Run("L1-H3-down", func(b *testing.B) {
		h := startConnectUDPProdH3DownloadHandle(b)
		defer h.close()
		b.ReportAllocs()
		b.SetBytes(masqueCPUBenchBytes)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			n, err := h.downloadOnce(masqueCPUBenchBytes)
			if err != nil {
				b.Fatal(err)
			}
			if n < masqueCPUBenchBytes {
				b.Fatalf("short download: %d want %d", n, masqueCPUBenchBytes)
			}
		}
	})
}

// TestMasqueConnectUDPCPUBudgetL0 anchors raw UDP sink upload ns/byte ceiling.
func TestMasqueConnectUDPCPUBudgetL0(t *testing.T) {
	measureConnectUDPCPUBudget(t, "L0", "udp_up", connectUDPL0UploadMaxNsPerB, runConnectUDPL0UploadOnce)
}

// TestMasqueConnectUDPCPUBudgetH3 anchors H3 CONNECT-UDP upload+download ns/byte and logs up/down vs Mbps.
func TestMasqueConnectUDPCPUBudgetH3(t *testing.T) {
	upH := startConnectUDPProdH3UploadHandle(t)
	defer upH.close()
	downH := startConnectUDPProdH3DownloadHandle(t)
	defer downH.close()

	up := measureConnectUDPCPUBudget(t, "L1-H3", "udp_up", connectUDPL1H3UploadMaxNsPerB, upH.uploadOnce)
	down := measureConnectUDPCPUBudget(t, "L1-H3", "udp_down", connectUDPL1H3DownloadMaxNsPerB, downH.downloadOnce)

	_, upMbps, err := benchConnectUDPProdProfileH3Upload(
		t, instantDatagramLink{}, connectUDPSynthProdBenchDuration, 0, connectudp.DefaultBenchUDPPayloadLen,
	)
	if err != nil {
		t.Fatalf("L1-H3 upload Mbps: %v", err)
	}
	_, downMbps, err := benchConnectUDPProdProfileH3Download(
		t, instantDatagramLink{}, connectUDPSynthProdBenchDuration, connectudp.DefaultBenchUDPPayloadLen,
	)
	if err != nil {
		t.Fatalf("L1-H3 download Mbps: %v", err)
	}
	logConnectUDPCPUPaired(t, "H3", upMbps, downMbps, up, down)
}

// TestMasqueConnectUDPCPUBudgetH2 anchors H2 CONNECT-UDP upload+download ns/byte and logs up/down vs Mbps.
func TestMasqueConnectUDPCPUBudgetH2(t *testing.T) {
	upH := startConnectUDPProdH2UploadHandle(t)
	defer upH.close()
	downH := startConnectUDPProdH2DownloadHandle(t)
	defer downH.close()

	up := measureConnectUDPCPUBudget(t, "L1-H2", "udp_up", connectUDPL1H2UploadMaxNsPerB, upH.uploadOnce)
	down := measureConnectUDPCPUBudget(t, "L1-H2", "udp_down", connectUDPL1H2DownloadMaxNsPerB, downH.downloadOnce)

	_, upMbps, err := benchConnectUDPProdProfileH2Upload(
		t, instantH2Link{}, connectUDPSynthProdBenchDuration, 0, connectudp.DefaultBenchUDPPayloadLen,
	)
	if err != nil {
		t.Fatalf("L1-H2 upload Mbps: %v", err)
	}
	_, downMbps, err := benchConnectUDPProdProfileH2Download(
		t, instantH2Link{}, connectUDPSynthProdBenchDuration, connectudp.DefaultBenchUDPPayloadLen,
	)
	if err != nil {
		t.Fatalf("L1-H2 download Mbps: %v", err)
	}
	logConnectUDPCPUPaired(t, "H2", upMbps, downMbps, up, down)
}

package masque

// CONNECT-UDP CPU budget gates: L0 raw UDP vs L1 full MASQUE ListenPacket upload (H3/H2 instant link).

import (
	"net"
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

const (
	connectUDPBenchPayloadLen     = connectudp.DefaultBenchUDPPayloadLen
	connectUDPBenchBytes          = 4 * 1024 * 1024
	connectUDPL0UploadMaxNsPerB   = 500.0    // loopback UDP sink, no MASQUE
	connectUDPL1H3UploadMaxNsPerB = 250000.0 // full H3 CONNECT-UDP stack (generous CI ceiling)
	connectUDPL1H2UploadMaxNsPerB = 250000.0 // full H2 capsule stack
)

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

	payload := make([]byte, connectUDPBenchPayloadLen)
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

// BenchmarkConnectUDPUploadLayer profiles per-layer CONNECT-UDP upload CPU (L0 / L1-H3 / L1-H2).
func BenchmarkConnectUDPUploadLayer(b *testing.B) {
	b.Run("L0", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(connectUDPBenchBytes)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			n, err := runConnectUDPL0UploadOnce(connectUDPBenchBytes)
			if err != nil {
				b.Fatal(err)
			}
			if n < connectUDPBenchBytes {
				b.Fatalf("short upload: %d want %d", n, connectUDPBenchBytes)
			}
		}
	})
	b.Run("L1-H3", func(b *testing.B) {
		h := startConnectUDPProdH3UploadHandle(b)
		defer h.close()
		b.ReportAllocs()
		b.SetBytes(connectUDPBenchBytes)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			n, err := h.uploadOnce(connectUDPBenchBytes)
			if err != nil {
				b.Fatal(err)
			}
			if n < connectUDPBenchBytes {
				b.Fatalf("short upload: %d want %d", n, connectUDPBenchBytes)
			}
		}
	})
	b.Run("L1-H2", func(b *testing.B) {
		h := startConnectUDPProdH2UploadHandle(b)
		defer h.close()
		b.ReportAllocs()
		b.SetBytes(connectUDPBenchBytes)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			n, err := h.uploadOnce(connectUDPBenchBytes)
			if err != nil {
				b.Fatal(err)
			}
			if n < connectUDPBenchBytes {
				b.Fatalf("short upload: %d want %d", n, connectUDPBenchBytes)
			}
		}
	})
}

func assertConnectUDPCPUBudget(t *testing.T, layer string, maxNsPerB float64, upload func(int64) (int64, error)) {
	t.Helper()
	result := testing.Benchmark(func(b *testing.B) {
		b.SetBytes(connectUDPBenchBytes)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			n, err := upload(connectUDPBenchBytes)
			if err != nil {
				b.Fatal(err)
			}
			if n < connectUDPBenchBytes {
				b.Fatalf("short upload: %d", n)
			}
		}
	})
	if result.N == 0 {
		t.Fatal("benchmark produced zero iterations")
	}
	nsPerByte := float64(result.NsPerOp()) / float64(connectUDPBenchBytes)
	if nsPerByte > maxNsPerB {
		t.Fatalf("connect-udp %s CPU budget: %.1f ns/B > %.0f ns/B", layer, nsPerByte, maxNsPerB)
	}
	t.Logf("connect-udp %s upload CPU: %.1f ns/B", layer, nsPerByte)
}

// TestMasqueConnectUDPCPUBudgetL0 anchors raw UDP sink upload ns/byte ceiling.
func TestMasqueConnectUDPCPUBudgetL0(t *testing.T) {
	assertConnectUDPCPUBudget(t, "L0", connectUDPL0UploadMaxNsPerB, runConnectUDPL0UploadOnce)
}

// TestMasqueConnectUDPCPUBudgetH3 anchors full H3 CONNECT-UDP prod upload path.
func TestMasqueConnectUDPCPUBudgetH3(t *testing.T) {
	h := startConnectUDPProdH3UploadHandle(t)
	defer h.close()
	assertConnectUDPCPUBudget(t, "L1-H3", connectUDPL1H3UploadMaxNsPerB, h.uploadOnce)
	_, mbps, err := benchConnectUDPProdProfileH3Upload(
		t, instantDatagramLink{}, connectUDPSynthProdBenchDuration, 0, connectUDPBenchPayloadLen,
	)
	if err != nil {
		t.Fatalf("L1-H3 burst Mbps: %v", err)
	}
	if mbps < connectUDPSynthProdBurstMinMbps {
		t.Fatalf("connect-udp L1-H3 burst slow: %.1f Mbit/s (want >= %.0f)", mbps, connectUDPSynthProdBurstMinMbps)
	}
	t.Logf("connect-udp L1-H3 burst: %.1f Mbit/s", mbps)
}

// TestMasqueConnectUDPCPUBudgetH2 anchors full H2 CONNECT-UDP prod upload path.
func TestMasqueConnectUDPCPUBudgetH2(t *testing.T) {
	h := startConnectUDPProdH2UploadHandle(t)
	defer h.close()
	assertConnectUDPCPUBudget(t, "L1-H2", connectUDPL1H2UploadMaxNsPerB, h.uploadOnce)
	_, mbps, err := benchConnectUDPProdProfileH2Upload(
		t, instantH2Link{}, connectUDPSynthProdBenchDuration, 0, connectUDPBenchPayloadLen,
	)
	if err != nil {
		t.Fatalf("L1-H2 burst Mbps: %v", err)
	}
	if mbps < connectUDPSynthProdBurstMinMbps {
		t.Fatalf("connect-udp L1-H2 burst slow: %.1f Mbit/s (want >= %.0f)", mbps, connectUDPSynthProdBurstMinMbps)
	}
	t.Logf("connect-udp L1-H2 burst: %.1f Mbit/s", mbps)
}

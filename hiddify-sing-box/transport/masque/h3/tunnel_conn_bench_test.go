package h3

import (
	"bytes"
	"io"
	"net"
	"testing"
)

const (
	tunnelConnWriteToBenchBytes  = 4 * 1024 * 1024
	tunnelConnWriteToMaxNsPerB   = 200.0
	tunnelConnWriteToFastMbps    = 80.0
)

func runTunnelConnWriteToDownloadOnce(data []byte) (int64, error) {
	c := NewPipeUploadTunnelConn(PipeUploadTunnelConnParams{
		Reader: io.NopCloser(bytes.NewReader(data)),
		Writer: nopWriteCloser{io.Discard},
		Local:  &net.TCPAddr{},
		Remote: &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 443},
	})
	return c.WriteTo(io.Discard)
}

// BenchmarkTunnelConnWriteToDownload (S87): CPU hotspot at TunnelConn.WriteTo on H3 reader path.
func BenchmarkTunnelConnWriteToDownload(b *testing.B) {
	data := make([]byte, tunnelConnWriteToBenchBytes)
	b.ReportAllocs()
	b.SetBytes(int64(tunnelConnWriteToBenchBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n, err := runTunnelConnWriteToDownloadOnce(data)
		if err != nil {
			b.Fatal(err)
		}
		if n < int64(tunnelConnWriteToBenchBytes) {
			b.Fatalf("short WriteTo: %d want %d", n, tunnelConnWriteToBenchBytes)
		}
	}
}

// TestMasqueConnectStreamCPUBudgetWriteTo (S87 gate): TunnelConn.WriteTo stays within ≤200 ns/B
// and instant ≥80 Mbit/s so downloadActive scheduling regressions surface before field KPI.
func TestMasqueConnectStreamCPUBudgetWriteTo(t *testing.T) {
	result := testing.Benchmark(BenchmarkTunnelConnWriteToDownload)
	if result.N == 0 {
		t.Fatal("benchmark produced zero iterations")
	}
	nsPerByte := float64(result.NsPerOp()) / float64(tunnelConnWriteToBenchBytes)
	if nsPerByte > tunnelConnWriteToMaxNsPerB {
		t.Fatalf("TunnelConn.WriteTo CPU budget: %.1f ns/B > %.0f ns/B", nsPerByte, tunnelConnWriteToMaxNsPerB)
	}

	secs := float64(result.NsPerOp()) / 1e9
	if secs <= 0 {
		secs = 1e-9
	}
	mbps := float64(tunnelConnWriteToBenchBytes*8) / secs / 1e6
	t.Logf("TunnelConn.WriteTo throughput: %.1f Mbit/s (CPU %.1f ns/B)", mbps, nsPerByte)
	if mbps < tunnelConnWriteToFastMbps {
		t.Fatalf("TunnelConn.WriteTo throughput slow: %.1f Mbit/s (want >= %.0f)", mbps, tunnelConnWriteToFastMbps)
	}
}

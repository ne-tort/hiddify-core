package h3

import (
	"bytes"
	"io"
	"testing"
)

const (
	interleaveBenchDownloadBytes = 4 * 1024 * 1024
	duplexCoordDownloadChunk       = 16 * 1024
)

// BenchmarkInterleaveDuplexTransfer (S102): CPU hotspot at duplex_coord.go interleave loop.
func BenchmarkInterleaveDuplexTransfer(b *testing.B) {
	download := bytes.Repeat([]byte("d"), interleaveBenchDownloadBytes)
	buf := make([]byte, duplexCoordDownloadChunk)

	b.ReportAllocs()
	b.SetBytes(interleaveBenchDownloadBytes)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		readIdx := 0
		_, err := interleaveDuplexTransfer(
			io.Discard,
			func(p []byte) (int, error) {
				if readIdx >= len(download) {
					return 0, io.EOF
				}
				n := copy(p, download[readIdx:])
				readIdx += n
				return n, nil
			},
			func() error { return nil },
			buf,
			func(int) {},
		)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// TestMasqueInterleaveDuplexTransferCPUBudget (S102 gate): interleaveDuplexTransfer stays
// within a generous ns/byte ceiling so scheduling regressions surface in CI.
func TestMasqueInterleaveDuplexTransferCPUBudget(t *testing.T) {
	result := testing.Benchmark(BenchmarkInterleaveDuplexTransfer)
	if result.N == 0 {
		t.Fatal("benchmark produced zero iterations")
	}
	const maxNsPerByte = 200.0
	nsPerByte := float64(result.NsPerOp()) / float64(interleaveBenchDownloadBytes)
	if nsPerByte > maxNsPerByte {
		t.Fatalf("interleaveDuplexTransfer CPU budget: %.1f ns/B > %.0f ns/B", nsPerByte, maxNsPerByte)
	}
}

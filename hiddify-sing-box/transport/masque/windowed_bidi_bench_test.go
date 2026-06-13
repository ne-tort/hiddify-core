package masque

import (
	"testing"
)

const windowedBidiBenchBytes = 512 * 1024

type windowedBidiThroughputSpec struct {
	name string
	link bidiLink
}

func windowedBidiThroughputSpecs() []windowedBidiThroughputSpec {
	return []windowedBidiThroughputSpec{
		{"L2_wide", benchWindowedWideBidiLink()},
		{"L3_ceiling", benchWindowedBidiLink()},
		{"L4_L256", benchWindowedBidiLinkL256()},
	}
}

func runWindowedBidiWriteToOnce(tb testing.TB, link bidiLink, nbytes int64) (int64, error) {
	h := startConnectStreamDownloadHarness(tb, link)
	defer h.close()
	return drainWriteToFixedBytes(h.conn, nbytes)
}

// BenchmarkWindowedBidiConnThroughput (S84): windowed bidi WriteTo throughput anchors L2/L3/L4
// (wide fast, 64 KiB ceiling, 256 KiB escape) under shared localize harness profile.
func BenchmarkWindowedBidiConnThroughput(b *testing.B) {
	for _, spec := range windowedBidiThroughputSpecs() {
		b.Run(spec.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(windowedBidiBenchBytes)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				n, err := runWindowedBidiWriteToOnce(b, spec.link, windowedBidiBenchBytes)
				if err != nil {
					b.Fatal(err)
				}
				if n < windowedBidiBenchBytes {
					b.Fatalf("short drain: %d want %d", n, windowedBidiBenchBytes)
				}
			}
		})
	}
}

// TestMasqueWindowedBidiConnThroughputBand (S84 gate): windowed WriteTo Mbps bands mirror localize
// verdict — L2 wide fast, L3 in ceiling band, L256 escapes ceiling max.
func TestMasqueWindowedBidiConnThroughputBand(t *testing.T) {
	const duration = localizeBenchDuration

	l2 := benchConnectStreamDownloadLayerWriteTo(t, "L2", benchWindowedWideBidiLink(), duration)
	l3 := benchConnectStreamDownloadLayerWriteTo(t, "L3", benchWindowedBidiLink(), duration)
	l256 := benchConnectStreamDownloadLayerWriteTo(t, "L256", benchWindowedBidiLinkL256(), duration)

	for _, r := range []connectStreamBenchResult{l2, l3, l256} {
		if r.err != nil {
			t.Fatalf("%s WriteTo: %v", r.layer, r.err)
		}
		if r.bytes < localizeBenchMinBytes {
			t.Fatalf("%s bytes=%d want >= %d", r.layer, r.bytes, localizeBenchMinBytes)
		}
		t.Logf("windowed bidi throughput %s WriteTo: %.1f Mbit/s (%d bytes)", r.layer, r.mbps, r.bytes)
	}

	assertConnectStreamFastLayer(t, l2)
	assertConnectStreamDownloadKPILayer(t, l3)
}

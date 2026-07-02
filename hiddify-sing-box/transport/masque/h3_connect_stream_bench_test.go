package masque

import (
	"testing"
	"time"
)

const connectStreamH3E2EBenchBytes = 2 * 1024 * 1024

type connectStreamH3E2EBenchSpec struct {
	name string
	link bidiLink
}

func connectStreamH3E2EBenchSpecs() []connectStreamH3E2EBenchSpec {
	return []connectStreamH3E2EBenchSpec{
		{"L256_strict", benchWindowedBidiLinkStrictH3L256()},
		{"L256_prod", benchWindowedBidiLinkH3Prod()},
	}
}

func runConnectStreamH3E2EDownloadOnce(tb testing.TB, link bidiLink, nbytes int64) (int64, error) {
	tb.Helper()
	h := startConnectStreamDownloadHarness(tb, link)
	defer h.close()
	return drainWriteToFixedBytes(h.conn, nbytes)
}

// BenchmarkConnectStreamH3EndToEndDownload (H3-L6): H3 CONNECT-stream WriteTo download CPU anchors
// strict L256 + prod eager S2C (parity BenchmarkConnectStreamH2EndToEndDownload).
func BenchmarkConnectStreamH3EndToEndDownload(b *testing.B) {
	for _, spec := range connectStreamH3E2EBenchSpecs() {
		b.Run(spec.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(connectStreamH3E2EBenchBytes)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				n, err := runConnectStreamH3E2EDownloadOnce(b, spec.link, connectStreamH3E2EBenchBytes)
				if err != nil {
					b.Fatal(err)
				}
				if n < connectStreamH3E2EBenchBytes {
					b.Fatalf("short h3 e2e drain: %d want %d", n, connectStreamH3E2EBenchBytes)
				}
			}
		})
	}
}

func benchConnectStreamH3DownloadLayerWriteTo(t *testing.T, layer string, link bidiLink, duration time.Duration) connectStreamBenchResult {
	t.Helper()
	h := startConnectStreamDownloadHarness(t, link)
	defer h.close()
	n, mbps, err := measureTCPDownloadWriteToMbps(h.conn, duration)
	return connectStreamBenchResult{layer: layer, mbps: mbps, bytes: n, err: err}
}

// TestMasqueConnectStreamH3LocalizeDownloadWriteTo (H3-L6) — L256 strict = wire-FC band (~60);
// L256 prod eager = prod QUIC path (must approach GATE-H3-SYNTH 200+ on fixes).
func TestMasqueConnectStreamH3LocalizeDownloadWriteTo(t *testing.T) {
	const duration = localizeBenchDuration

	strict := benchConnectStreamH3DownloadLayerWriteTo(t, "L256_strict", benchWindowedBidiLinkStrictH3L256(), duration)
	prod := benchConnectStreamH3DownloadLayerWriteTo(t, "L256_prod", benchWindowedBidiLinkH3Prod(), duration)

	for _, r := range []connectStreamBenchResult{strict, prod} {
		if r.err != nil {
			t.Fatalf("%s WriteTo download: %v", r.layer, r.err)
		}
		t.Logf("h3 connect-stream download %s WriteTo: %.1f Mbit/s (%d bytes)", r.layer, r.mbps, r.bytes)
	}

	if strict.mbps < connectStreamVPSKPITargetDownMbps {
		t.Fatalf("%s", synthKPIDiagnostic("[H3-L1c wire L256]", "tcp_down", strict.mbps,
			connectStreamVPSKPITargetDownMbps, "weak floor; wire ceiling ~60 Mbit/s"))
	}
	if strict.mbps >= connectStreamSynthProdMinMbps {
		t.Fatalf("strict L256 unexpectedly >= %.0f Mbit/s (%.1f) — harness no longer models wire ceiling",
			connectStreamSynthProdMinMbps, strict.mbps)
	}
	if prod.mbps < connectStreamLocalizeFastMbps {
		t.Fatalf("%s", synthKPIDiagnostic("[H3-L1c prod eager L256 harness]", "tcp_down WriteTo", prod.mbps,
			connectStreamLocalizeFastMbps, "harness only — GATE-H3-SYNTH 200+ is TestGATEH3Synth* prod stack"))
	}
}

// TestH3ConnectStreamH2ParityStrictL256Download (H3-T6-07) — H3 download on strict L256 bidi wrap
// must stay within 50% of H2 on the same window model (strict link, H2 eager WINDOW off).
func TestH3ConnectStreamH2ParityStrictL256Download(t *testing.T) {
	t.Setenv("MASQUE_H2_DOWNLOAD_EAGER_WINDOW", "0")
	const duration = localizeBenchDuration

	h2 := benchConnectStreamH2DownloadLayerWriteTo(t, "H2_L256", benchWindowedBidiLinkL256(), duration)
	h3 := benchConnectStreamH3DownloadLayerWriteTo(t, "H3_L256", benchWindowedBidiLinkStrictH3L256(), duration)

	for _, r := range []connectStreamBenchResult{h2, h3} {
		if r.err != nil {
			t.Fatalf("%s WriteTo: %v", r.layer, r.err)
		}
		t.Logf("H2/H3 strict L256 %s WriteTo: %.1f Mbit/s (%d bytes)", r.layer, r.mbps, r.bytes)
	}

	if h2.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("H2 strict L256 anchor slow: %.1f Mbit/s (want > %.0f)", h2.mbps, connectStreamVPSKPITargetDownMbps)
	}
	minH3 := h2.mbps * 0.5
	if h3.mbps < minH3 {
		t.Fatalf("H3 strict L256 download %.1f Mbit/s (want >= 50%% of H2 L256 %.1f = %.1f)",
			h3.mbps, h2.mbps, minH3)
	}
}

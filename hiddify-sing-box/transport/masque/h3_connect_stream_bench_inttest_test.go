//go:build masque_inttest_heavy

package masque

import (
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestH3ConnectStreamH2ParityStrictL256Download — H3 download on strict L256 within 50% of H2.
func TestH3ConnectStreamH2ParityStrictL256Download(t *testing.T) {
	http2.SetMasqueDownloadEagerWindowEnabled(false)
	t.Cleanup(func() { http2.SetMasqueDownloadEagerWindowEnabled(true) })
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

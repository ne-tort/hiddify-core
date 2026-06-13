package masque

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/h3"
)

// Simnet KPI anchor (replace/quic-go-patched masque_duplex_simnet_test.go S14/S96).
const (
	masqueSimnetKPIAnchorMbps = 14.5
	masqueSimnetKPIBandPct    = 0.35
)

// TestMasqueSimnetWindowedHarnessParity (S112): L2 windowed WriteTo Mbps within ±35% of simnet
// anchor (14.5 Mbit/s @ 35 ms RTT, 64 KiB credit) — cross-layer parity guard.
func TestMasqueSimnetWindowedHarnessParity(t *testing.T) {
	h := startConnectStreamDownloadHarness(t, benchWindowedBidiLink())
	defer h.close()

	n, mbps, err := measureTCPDownloadWriteToMbps(h.conn, localizeBenchDuration)
	if err != nil {
		t.Fatalf("windowed WriteTo: %v", err)
	}
	if n < localizeBenchMinBytes {
		t.Fatalf("bytes=%d want >= %d", n, localizeBenchMinBytes)
	}
	if h3.DownloadEagerWindowEnabled() {
		t.Logf("S112 windowed harness (eager WINDOW): %.1f Mbit/s (KPI > %.0f)", mbps, connectStreamVPSKPITargetDownMbps)
		assertConnectStreamWindowedCeilingBand(t, mbps, "S112 eager window harness")
		return
	}
	minMbps := masqueSimnetKPIAnchorMbps * (1 - masqueSimnetKPIBandPct)
	maxMbps := masqueSimnetKPIAnchorMbps * (1 + masqueSimnetKPIBandPct)
	t.Logf("S112 windowed harness: %.1f Mbit/s (simnet anchor %.1f ±%.0f%%)",
		mbps, masqueSimnetKPIAnchorMbps, masqueSimnetKPIBandPct*100)
	if mbps < minMbps || mbps > maxMbps {
		t.Fatalf("harness %.1f Mbit/s outside simnet band %.1f–%.1f",
			mbps, minMbps, maxMbps)
	}
}

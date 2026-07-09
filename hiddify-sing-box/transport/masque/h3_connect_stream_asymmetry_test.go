package masque_test

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/h3"
)

const h3AsymmetryMinDownMbps = 21.0

// benchWindowedBidiLinkStrictH3L256 uses prod 256 KiB window anchor @35ms RTT.
func benchWindowedBidiLinkStrictH3L256() float64 {
	return h3.ExportBenchWindowedBidiLinkRTT(35*time.Millisecond, h3.TunnelWriteToBufLen)
}

// TestH3ConnectStreamBidiAsymmetryRatio (H3-D synth): windowed download KPI @256 KiB window.
func TestH3ConnectStreamBidiAsymmetryRatio(t *testing.T) {
	down := benchWindowedBidiLinkStrictH3L256()
	t.Logf("benchWindowedBidiLinkStrictH3L256=%.1f Mbit/s", down)
	if down < h3AsymmetryMinDownMbps {
		t.Fatalf("download %.1f Mbit/s want >= %.0f", down, h3AsymmetryMinDownMbps)
	}
}

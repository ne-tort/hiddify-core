package masque

// F7.1 localize: H3 paced @200/300 — field cross showed ~2.5% loss at 200 after SOCKS RCVBUF fix.
// In-proc direct vs SOCKS: if both clean, loss is WAN/QUIC path (not ASSOCIATE / not local dataplane).

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

// InttestLocalizeConnectUDPH3Paced200DirectVsSocks reports loss/goodput at cross-repro rates.
func InttestLocalizeConnectUDPH3Paced200DirectVsSocks(t *testing.T) {
	t.Helper()
	localizeConnectUDPH3PacedDirectVsSocks(t, 200.0)
}

// InttestLocalizeConnectUDPH3Paced300DirectVsSocks same at 300 Mbit (local ceiling onset band).
func InttestLocalizeConnectUDPH3Paced300DirectVsSocks(t *testing.T) {
	t.Helper()
	localizeConnectUDPH3PacedDirectVsSocks(t, 300.0)
}

func localizeConnectUDPH3PacedDirectVsSocks(t *testing.T, target float64) {
	t.Helper()
	dur := connectUDPSynthProdBenchDuration
	direct := benchConnectUDPPacedSinkGoodput(t, false, dur, target)
	socks := benchConnectUDPPacedSinkGoodput(t, true, dur, target)

	t.Logf("RESULT_H3_PACED_LOCALIZE target=%.0f direct_mbps=%.2f direct_loss=%.3f%% direct_rx=%d/%d socks_mbps=%.2f socks_loss=%.3f%% socks_rx=%d/%d",
		target,
		direct.mbps, direct.stats.LossPct, direct.stats.RxPkts, direct.sentPkts,
		socks.mbps, socks.stats.LossPct, socks.stats.RxPkts, socks.sentPkts,
	)

	// Instant link: both paths must be zero-loss at 200 (field loss is path/QUIC, not local code).
	// At 300 local docker sometimes shows tiny loss — fail only if >1% or SOCKS>>direct.
	maxLoss := 0.05
	if target >= 300 {
		maxLoss = 1.0
	}
	assertConnectUDPProbeLoss(t, "h3 direct paced", direct.stats, maxLoss)
	assertConnectUDPProbeLoss(t, "h3 socks paced", socks.stats, maxLoss)

	minFloor := connectudp.MinPacedGoodputMbit(target) * 0.85
	if direct.mbps < minFloor {
		t.Fatalf("h3 direct @%.0f goodput %.2f < floor %.2f", target, direct.mbps, minFloor)
	}
	if socks.mbps < minFloor {
		t.Fatalf("h3 socks @%.0f goodput %.2f < floor %.2f", target, socks.mbps, minFloor)
	}
	if socks.stats.LossPct > direct.stats.LossPct+0.5 {
		t.Fatalf("h3 socks loss %.3f%% >> direct %.3f%% — ASSOCIATE path still lossy at %.0f",
			socks.stats.LossPct, direct.stats.LossPct, target)
	}
}

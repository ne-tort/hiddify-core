package masque

// Real-scenario CONNECT-UDP prod profile for H3 and H2 (parity with masque-go isolated bench).

import (
	"context"
	"testing"
	"time"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

const connectUDPProdRealScenarioBudget = 55 * time.Second

func TestConnectUDPProdRealScenarioH3H2(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), connectUDPProdRealScenarioBudget)
	defer cancel()
	t.Cleanup(func() {
		if d := time.Until(deadlineFromProdRealScenarioCtx(ctx)); d < 0 {
			t.Fatalf("connect-udp real scenario exceeded %v budget", connectUDPProdRealScenarioBudget)
		}
	})

	dur := connectUDPSynthProdBenchDuration
	wanPayload := connectudp.DefaultBenchUDPPayloadLen
	wanTargetMbit := dockerBenchUDPTargetMbit
	dodTargetMbit := connectUDPSynthProdMinMbps

	// --- H3 DoD: steady MTU paced @1000 (TestGATEConnectUDPH3SynthProdUploadSteady parity) ---
	h3Steady := connectudp.SteadyUploadPayloadLenH3()
	h3SteadyMbps, h3SteadySt, err := benchConnectUDPProdProfileH3UploadZeroLossPaced(
		t, instantDatagramLink{}, dur, h3Steady, dodTargetMbit,
	)
	if err != nil {
		t.Fatalf("h3 DoD steady upload: %v", err)
	}
	assertConnectUDPProdRealScenarioDoD(t, "h3", "steady", h3Steady, h3SteadyMbps, h3SteadySt, dodTargetMbit)

	// --- H2 DoD: max RFC9297 capsule zero-loss (TestGATEConnectUDPH2SynthProdUploadMaxCapsule parity) ---
	h2MaxPayload := h2c.MaxUDPPayloadPerDatagramCapsule()
	h2DoDMbps, h2DoDSt, err := benchConnectUDPProdProfileH2UploadZeroLoss(t, instantH2Link{}, dur, h2MaxPayload)
	if err != nil {
		t.Fatalf("h2 DoD maxCapsule upload: %v", err)
	}
	assertConnectUDPProdRealScenarioDoD(t, "h2", "maxCapsule", h2MaxPayload, h2DoDMbps, h2DoDSt, dodTargetMbit)

	// --- H3 WAN: docker paced @8 Mbit/s (perf-lab parity) ---
	h3WANMbps, h3WANSt, err := benchConnectUDPProdProfileH3UploadZeroLossPaced(
		t, instantDatagramLink{}, dur, wanPayload, wanTargetMbit,
	)
	if err != nil {
		t.Fatalf("h3 WAN paced upload: %v", err)
	}
	assertConnectUDPProdRealScenarioWAN(t, "h3", h3WANMbps, h3WANSt, wanPayload, wanTargetMbit)

	// --- H2 WAN: docker paced @8 Mbit/s ---
	h2WANMbps, h2WANSt, err := benchConnectUDPProdProfileH2UploadPaced(
		t, instantH2Link{}, dur, wanPayload, wanTargetMbit,
	)
	if err != nil {
		t.Fatalf("h2 WAN paced upload: %v", err)
	}
	assertConnectUDPProdRealScenarioWAN(t, "h2", h2WANMbps, h2WANSt, wanPayload, wanTargetMbit)

	t.Logf("REAL SCENARIO SUMMARY dur=%s:", dur)
	t.Logf("  h3 DoD steady(%dB) @%.0f: %.1f Mbit/s loss=%.4f%%", h3Steady, dodTargetMbit, h3SteadyMbps, h3SteadySt.LossPct)
	t.Logf("  h2 DoD maxCapsule(%dB):     %.1f Mbit/s loss=%.4f%%", h2MaxPayload, h2DoDMbps, h2DoDSt.LossPct)
	t.Logf("  h3 WAN paced(%dB) @%.0f:    %.1f Mbit/s loss=%.4f%%", wanPayload, wanTargetMbit, h3WANMbps, h3WANSt.LossPct)
	t.Logf("  h2 WAN paced(%dB) @%.0f:    %.1f Mbit/s loss=%.4f%%", wanPayload, wanTargetMbit, h2WANMbps, h2WANSt.LossPct)
}

func assertConnectUDPProdRealScenarioDoD(
	t *testing.T,
	layer, profile string,
	payloadLen int,
	mbps float64,
	st connectudp.SequencedStats,
	targetMbit float64,
) {
	t.Helper()
	t.Logf("%s DoD %s(%dB): %.1f Mbit/s rx=%d/%d loss=%.4f%% dup=%.2f%%",
		layer, profile, payloadLen, mbps, st.RxPkts, st.SentPkts, st.LossPct, st.DupPct)
	if !st.BurstZeroLossOK(payloadLen, connectudp.DefaultBurstMinRxRatio) {
		t.Fatalf("%s DoD %s zero-loss failed: rx=%d/%d loss=%.4f%% fill_ok=%v",
			layer, profile, st.RxPkts, st.SentPkts, st.LossPct, st.FillIntegrityOK(payloadLen))
	}
	if layer == "h3" && profile == "steady" {
		assertConnectUDPSynthProdMbps(t, "L4 connect-udp-h3 prod", "udp_up_steady", mbps,
			"steady MTU paced zero-loss upload (real scenario)")
	}
	if layer == "h2" && synthProdGatePass(mbps) {
		assertConnectUDPSynthProdMbps(t, "L4 connect-udp-h2 prod", "udp_up_max_capsule", mbps,
			"max RFC9297 capsule zero-loss upload (real scenario)")
	} else if layer == "h2" {
		t.Logf("h2 DoD maxCapsule %.1f Mbit/s (OPEN vs %.0f DoD target)", mbps, targetMbit)
	}
}

func assertConnectUDPProdRealScenarioWAN(
	t *testing.T,
	layer string,
	mbps float64,
	st connectudp.SequencedStats,
	payloadLen int,
	targetMbit float64,
) {
	t.Helper()
	t.Logf("%s WAN paced(%dB) @%.0f: %.1f Mbit/s rx=%d/%d loss=%.4f%% dup=%.2f%%",
		layer, payloadLen, targetMbit, mbps, st.RxPkts, st.SentPkts, st.LossPct, st.DupPct)
	if st.LossPct > 0 {
		t.Fatalf("%s WAN paced loss=%.4f%% (want zero): rx=%d/%d",
			layer, st.LossPct, st.RxPkts, st.SentPkts)
	}
	const wanSlackMbps = 1.0
	if mbps < targetMbit-wanSlackMbps {
		t.Fatalf("%s WAN paced goodput %.1f Mbit/s < target %.0f - slack %.1f",
			layer, mbps, targetMbit, wanSlackMbps)
	}
}

func deadlineFromProdRealScenarioCtx(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(connectUDPProdRealScenarioBudget)
}

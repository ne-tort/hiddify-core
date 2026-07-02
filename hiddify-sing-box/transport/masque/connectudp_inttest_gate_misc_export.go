package masque

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

func InttestLocalizeConnectUDPH2UploadSharedTransportVsNewTransport(t *testing.T) {
	t.Setenv("MASQUE_H2_CONNECT_UDP_ASYMMETRIC_DUPLEX", "1")
	dur := connectUDPSynthProdBenchDuration
	_, sharedMbps, err := benchConnectUDPH2OverlayDirectUpload(t, instantH2Link{}, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("shared EnsureTransport upload: %v", err)
	}
	_, prodMbps, err := benchConnectUDPH2OverlayProdShapedUpload(t, instantH2Link{}, dur, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("prod NewTransport upload: %v", err)
	}
	ratio := prodMbps / sharedMbps
	minRatio := 0.85 * (1 - connectUDPSynthInstantGateSlackPct)
	maxRatio := 1.15 * (1 + connectUDPSynthInstantGateSlackPct)
	t.Logf("LOCALIZE h2 upload shared=%.1f prod_NewTransport=%.1f ratio=%.2f (want %.2f–%.2f when shared>=300)",
		sharedMbps, prodMbps, ratio, minRatio, maxRatio)
	if sharedMbps >= 300 && (ratio < minRatio || ratio > maxRatio) {
		t.Fatalf("NewTransport vs EnsureTransport upload gap (shared=%.1f prod=%.1f ratio=%.2f)",
			sharedMbps, prodMbps, ratio)
	}
}

func InttestConnectUDPSynthFailFastWallContract(t *testing.T) {
	t.Parallel()
	if connectUDPSynthUploadWriteStall > time.Second {
		t.Fatalf("upload write stall %v must be <= 1s (fail fast)", connectUDPSynthUploadWriteStall)
	}
	maxLeg := connectUDPSynthProdBenchDuration + connectUDPSynthStabilityWallSlack
	if maxLeg > 10*time.Second {
		t.Fatalf("synth bench max wall %v must be <= 10s per leg", maxLeg)
	}
	if connectUDPSynthGateWaitCtx > 8*time.Second {
		t.Fatalf("gate wait ctx %v must be <= 8s", connectUDPSynthGateWaitCtx)
	}
	if connectUDPSynthGateParallelWaitCtx > 15*time.Second {
		t.Fatalf("gate parallel wait ctx %v must be <= 15s", connectUDPSynthGateParallelWaitCtx)
	}
}

func InttestGATEConnectUDPParallelScalingH2(t *testing.T) {
	gateConnectUDPParallelScaling(t, "h2", 4)
}

func InttestGATEConnectUDPParallelScalingH3(t *testing.T) {
	gateConnectUDPParallelScaling(t, "h3", 4)
}

func InttestLocalizeConnectUDPH3ParallelScalingAttribution(t *testing.T) {
	localizeConnectUDPH3ParallelScalingAttribution(t)
}

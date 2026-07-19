package masque

import (
	"testing"
	"time"
)

func InttestConnectUDPSynthFailFastWallContract(t *testing.T) {
	t.Parallel()
	if connectUDPSynthUploadWriteStall > time.Second {
		t.Fatalf("upload write stall %v must be <= 1s (fail fast)", connectUDPSynthUploadWriteStall)
	}
	maxLeg := connectUDPSynthProdBenchDuration + connectUDPSynthStabilityWallSlack
	if maxLeg > 10*time.Second {
		t.Fatalf("synth bench max wall %v must be <= 10s per leg", maxLeg)
	}
	if connectUDPSynthGateWaitCtx > 5*time.Second {
		t.Fatalf("gate wait ctx %v must be <= 5s", connectUDPSynthGateWaitCtx)
	}
	if connectUDPSynthGateParallelWaitCtx > 10*time.Second {
		t.Fatalf("gate parallel wait ctx %v must be <= 10s", connectUDPSynthGateParallelWaitCtx)
	}
}

func InttestGATEConnectUDPParallelScalingH2(t *testing.T) {
	gateConnectUDPParallelScaling(t, "h2", 4)
}

func InttestGATEConnectUDPParallelScalingH3(t *testing.T) {
	gateConnectUDPParallelScaling(t, "h3", 4)
}

func InttestGATEConnectUDPScalingMapH2(t *testing.T) {
	gateConnectUDPScalingMap(t, "h2")
}

func InttestGATEConnectUDPScalingMapH3(t *testing.T) {
	gateConnectUDPScalingMap(t, "h3")
}

func InttestLocalizeConnectUDPH3ParallelScalingAttribution(t *testing.T) {
	localizeConnectUDPH3ParallelScalingAttribution(t)
}

package masque_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque"
)

// TestGATEH2AsymHypothesisChunk64DockerFalsified locks Docker bisect H1: 256→64 KiB did not fix upload asym.
func TestGATEH2AsymHypothesisChunk64DockerFalsified(t *testing.T) {
	assertHypothesisFalsified(t, "H1-CHUNK-64",
		masque.ExportConnectStreamH2AsymDockerBaselineUpMbps,
		masque.ExportConnectStreamH2AsymChunk64BisectUpMbps)
}

// TestGATEH2AsymHypothesisEagerWindowDockerFalsified locks Docker bisect H2: eager WINDOW off did not fix upload asym.
func TestGATEH2AsymHypothesisEagerWindowDockerFalsified(t *testing.T) {
	assertHypothesisFalsified(t, "H2-EAGER-WINDOW",
		masque.ExportConnectStreamH2AsymDockerBaselineUpMbps,
		masque.ExportConnectStreamH2AsymEagerOffBisectUpMbps)
}

// TestGATEH2AsymHypothesisRelayUploadWakeDockerFalsified locks Docker bisect H3: server upload wake off did not fix upload asym.
func TestGATEH2AsymHypothesisRelayUploadWakeDockerFalsified(t *testing.T) {
	assertHypothesisFalsified(t, "H3-RELAY-UPLOAD-WAKE",
		masque.ExportConnectStreamH2AsymDockerBaselineUpMbps,
		masque.ExportConnectStreamH2AsymRelayWakeOffBisectUpMbps)
}

func assertHypothesisFalsified(t *testing.T, id string, baseUp, bisectUp float64) {
	t.Helper()
	uplift := hypothesisUplift(baseUp, bisectUp)
	maxUplift := masque.ExportConnectStreamH2AsymHypothesisMinUplift
	if uplift > maxUplift {
		t.Fatalf("%s CONFIRMED upload uplift %.1f%% > %.0f%% — update ledger (base=%.0f bisect=%.0f)",
			id, uplift*100, maxUplift*100, baseUp, bisectUp)
	}
	t.Logf("%s FALSIFIED: Docker upload %.0f→%.0f Mbit/s (%.1f%% uplift vs baseline)",
		id, baseUp, bisectUp, uplift*100)
}

// hypothesisUplift returns fractional upload improvement of variant over baseline.
func hypothesisUplift(baselineUp, variantUp float64) float64 {
	if baselineUp <= 0 {
		return 0
	}
	return (variantUp - baselineUp) / baselineUp
}

// TestGATEH2AsymPlatformGapSynthSymmetric documents that in-proc synth can be symmetric while Docker H2 upload asym exists.
func TestGATEH2AsymPlatformGapSynthSymmetric(t *testing.T) {
	dur := masque.ExportConnectStreamSynthSequentialBenchDuration
	targetDown := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
	targetUp := masque.ExportStartH2ConnectStreamUploadTarget(t)
	proxyPort := startLaunchMasqueStackH2ConnectStreamServer(t)
	socksPort := masque.ExportStartH2ConnectStreamSocksRouter(t, proxyPort)

	_, downMbps := measureProdStackDownloadMbps(t, socksPort, targetDown, dur)
	_, upMbps := measureProdStackUploadMbps(t, socksPort, targetUp, dur)
	if downMbps <= 0 || upMbps <= 0 {
		t.Fatal("zero Mbps on synth sequential legs")
	}
	synthRatio := upMbps / downMbps
	if synthRatio > downMbps/upMbps {
		synthRatio = downMbps / upMbps
	}
	dockerRatio := masque.ExportConnectStreamH2AsymDockerBaselineUpMbps / masque.ExportConnectStreamH2AsymDockerBaselineDownMbps

	t.Logf("platform gap: synth WriteTo ratio min/max=%.2f (up=%.0f down=%.0f); Docker Read/-R ratio up/down=%.2f",
		synthRatio, upMbps, downMbps, dockerRatio)

	if synthRatio < dockerRatio {
		t.Fatalf("synth ratio %.2f worse than Docker %.2f — update platform-gap gate", synthRatio, dockerRatio)
	}
	if dockerRatio >= 0.85 {
		t.Fatalf("Docker baseline ratio %.2f already symmetric — update ledger constants", dockerRatio)
	}
}

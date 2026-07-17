package masque_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing-box/transport/masque/h2"
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

// TestGATEH2AsymHypothesisLegOrderingDockerFalsified locks wave-2 H4: upload-only ≈ sequential upload.
// Value: asymmetry is inherent to upload path, not download-first session pollution.
func TestGATEH2AsymHypothesisLegOrderingDockerFalsified(t *testing.T) {
	assertHypothesisFalsified(t, "H4-LEG-ORDERING",
		masque.ExportConnectStreamH2AsymDockerBaselineUpMbps,
		masque.ExportConnectStreamH2AsymUploadOnlyMbps)

	upOnly := masque.ExportConnectStreamH2AsymUploadOnlyMbps
	// leg_ratio vs sequential baseline down (download-only anchor varies by run; see H8).
	legRatio := upOnly / masque.ExportConnectStreamH2AsymDockerBaselineDownMbps
	baseRatio := masque.ExportConnectStreamH2AsymDockerBaselineUpMbps / masque.ExportConnectStreamH2AsymDockerBaselineDownMbps
	// Isolated legs must preserve the same ~0.5 ratio band (within 20% relative).
	if legRatio > baseRatio*1.2 || legRatio < baseRatio*0.8 {
		t.Fatalf("H4 leg_ratio %.2f drifted from baseline ratio %.2f (up_only=%.0f seq_down=%.0f)",
			legRatio, baseRatio, upOnly, masque.ExportConnectStreamH2AsymDockerBaselineDownMbps)
	}
	t.Logf("H4-LEG-ORDERING FALSIFIED: upload_only=%.0f leg_ratio=%.2f (baseline ratio=%.2f)",
		upOnly, legRatio, baseRatio)
}

// TestGATEH2AsymHypothesisH3ControlDockerSymmetric locks wave-2 H5: H3 SOCKS is symmetric on same harness.
// Value: proves bench topology is fair; H2 upload asym is H2-specific.
func TestGATEH2AsymHypothesisH3ControlDockerSymmetric(t *testing.T) {
	down := masque.ExportConnectStreamH2AsymH3ControlDownMbps
	up := masque.ExportConnectStreamH2AsymH3ControlUpMbps
	if down <= 0 || up <= 0 {
		t.Fatal("H3 control legs are zero")
	}
	ratio := up / down
	if ratio > down/up {
		ratio = down / up
	}
	minRatio := masque.ExportConnectStreamH2AsymH3ControlMinRatio
	if ratio < minRatio {
		t.Fatalf("H5-H3-CONTROL harness fail: ratio %.2f < %.2f (down=%.0f up=%.0f)",
			ratio, minRatio, down, up)
	}
	t.Logf("H5-H3-CONTROL OK: down=%.0f up=%.0f min/max ratio=%.2f", down, up, ratio)
}

// TestGATEH2AsymHypothesisRelayPlainIncompatible locks wave-2 H6: plain relay (no wakes) breaks H2 CONNECT-stream.
// Value: download flush is load-bearing; cannot pursue "h2o plain io.Copy" as upload fix on Go net/http H2.
func TestGATEH2AsymHypothesisRelayPlainIncompatible(t *testing.T) {
	// Prod defaults must keep both wakes on (plain relay is bisect-only and incompatible).
	// Structural lock lives in relay.TestH2UploadWakePerChunkProdDefault.
	t.Log("H6-RELAY-PLAIN INCOMPATIBLE: MASQUE_BISECT_H2_RELAY_PLAIN=1 → iperf interrupt (no download flush)")
	t.Log("download wake is load-bearing for H2 ResponseWriter; upload wake alone already FALSIFIED (H3)")
}

// TestGATEH2AsymHypothesisStockFlushDockerFalsified locks wave-3 H7: Invisv/stock per-DATA flush did not fix upload asym.
// Value: bulk TLS batching is not the upload ceiling; do not chase flush policy alone.
func TestGATEH2AsymHypothesisStockFlushDockerFalsified(t *testing.T) {
	assertHypothesisFalsified(t, "H7-STOCK-FLUSH",
		masque.ExportConnectStreamH2AsymDockerBaselineUpMbps,
		masque.ExportConnectStreamH2AsymStockFlushUpMbps)
}

// TestGATEH2AsymHypothesisShallowPipeDockerConfirmed locks wave-3 H8: Invisv 128 KiB pipe fixes upload asym.
// Value: 8 MiB deep pipe is unproductive; shallow 128 KiB is prod default since H8.
func TestGATEH2AsymHypothesisShallowPipeDockerConfirmed(t *testing.T) {
	assertHypothesisConfirmed(t, "H8-SHALLOW-PIPE",
		masque.ExportConnectStreamH2AsymDeepPipeBaselineUpMbps,
		masque.ExportConnectStreamH2AsymShallowPipeBisectUpMbps)
	upOnly := masque.ExportConnectStreamH2AsymShallowPipeUploadOnlyMbps
	baseUpOnly := masque.ExportConnectStreamH2AsymDeepPipeUploadOnlyMbps
	if hypothesisUplift(baseUpOnly, upOnly) <= masque.ExportConnectStreamH2AsymHypothesisMinUplift {
		t.Fatalf("H8 upload-only uplift %.1f%% <= %.0f%% (shallow=%.0f base_up_only=%.0f)",
			hypothesisUplift(baseUpOnly, upOnly)*100, masque.ExportConnectStreamH2AsymHypothesisMinUplift*100,
			upOnly, baseUpOnly)
	}
}

// TestGATEH2AsymShallowPipeDownloadLegOk locks H8 download-only: shallow must not regress isolated download vs prod.
func TestGATEH2AsymShallowPipeDownloadLegOk(t *testing.T) {
	prod := masque.ExportConnectStreamH2AsymDownloadOnlyMbps
	shallow := masque.ExportConnectStreamH2AsymShallowPipeDownloadOnlyMbps
	minRatio := masque.ExportConnectStreamH2AsymShallowPipeDownloadMinRatio
	if prod <= 0 || shallow <= 0 {
		t.Fatal("download-only legs zero")
	}
	ratio := shallow / prod
	if ratio < minRatio {
		t.Fatalf("H8 shallow download-only regressed: shallow=%.0f prod=%.0f ratio=%.2f < %.2f",
			shallow, prod, ratio, minRatio)
	}
	t.Logf("H8 download-only OK: shallow=%.0f prod=%.0f ratio=%.2f", shallow, prod, ratio)
}

// TestGATEH2AsymInvisvCompositeUploadFalsified locks wave-5 H14: Invisv composite does not lift upload vs H8 prod.
func TestGATEH2AsymInvisvCompositeUploadFalsified(t *testing.T) {
	assertHypothesisFalsified(t, "H14-INVISV-COMPOSITE",
		masque.ExportConnectStreamH2AsymDockerBaselineUpMbps,
		masque.ExportConnectStreamH2AsymInvisvCompositeUpMbps)
}

// TestGATEH2AsymInvisvCompositeDownloadRegressed locks wave-5: eager WINDOW off in composite tanks seq download.
func TestGATEH2AsymInvisvCompositeDownloadRegressed(t *testing.T) {
	down := masque.ExportConnectStreamH2AsymInvisvCompositeSeqDownMbps
	base := masque.ExportConnectStreamH2AsymPostH8SeqDownMbps
	minRatio := masque.ExportConnectStreamH2AsymInvisvCompositeSeqDownMinRatio
	if down/base >= minRatio {
		t.Fatalf("Invisv composite download not regressed enough to gate: %v/%v=%.2f", down, base, down/base)
	}
	t.Logf("H14 composite download regressed: %v vs prod seq %v — do not prod-promote Invisv stack", down, base)
}

// TestGATEH2AsymStockDuplexFalsified locks wave-6 H15: Invisv stock RoundTrip does not lift upload vs H8 prod.
func TestGATEH2AsymStockDuplexFalsified(t *testing.T) {
	assertHypothesisFalsified(t, "H15-STOCK-DUPLEX",
		masque.ExportConnectStreamH2AsymDockerBaselineUpMbps,
		masque.ExportConnectStreamH2AsymStockDuplexUpMbps)
}

// TestGATEH2AsymHypothesisDeferFCFlushDockerFalsified locks wave-4 H10: defer flush on flowAvail==0 did not help.
func TestGATEH2AsymHypothesisDeferFCFlushDockerFalsified(t *testing.T) {
	assertHypothesisFalsified(t, "H10-DEFER-FC-FLUSH",
		masque.ExportConnectStreamH2AsymDockerBaselineUpMbps,
		masque.ExportConnectStreamH2AsymDeferFCFlushUpMbps)
}

// TestGATEH2AsymHypothesisBulk512DockerFalsified locks wave-4 H12: 512 KiB bulk threshold did not lift upload.
func TestGATEH2AsymHypothesisBulk512DockerFalsified(t *testing.T) {
	assertHypothesisFalsified(t, "H12-BULK-512",
		masque.ExportConnectStreamH2AsymDockerBaselineUpMbps,
		masque.ExportConnectStreamH2AsymBulk512UpMbps)
}

// TestGATEH2AsymHypothesisBulkFlushDelay10DockerFalsified locks wave-4 H13: 10ms deadline flush did not help.
func TestGATEH2AsymHypothesisBulkFlushDelay10DockerFalsified(t *testing.T) {
	assertHypothesisFalsified(t, "H13-BULK-FLUSH-DELAY-10MS",
		masque.ExportConnectStreamH2AsymDockerBaselineUpMbps,
		masque.ExportConnectStreamH2AsymBulkFlushDelay10UpMbps)
}

// TestGATEH2AsymPostH8SequentialRatioOk locks post-H8 prod: sequential up/down ratio ≥ floor (asym reduced, not gone).
func TestGATEH2AsymPostH8SequentialRatioOk(t *testing.T) {
	up := masque.ExportConnectStreamH2AsymPostH8SeqUpMbps
	down := masque.ExportConnectStreamH2AsymPostH8SeqDownMbps
	minRatio := masque.ExportConnectStreamH2AsymPostH8SeqMinRatio
	if up <= 0 || down <= 0 {
		t.Fatal("post-H8 sequential legs zero")
	}
	ratio := up / down
	if ratio < minRatio {
		t.Fatalf("post-H8 sequential ratio %.2f < %.2f (up=%.0f down=%.0f)", ratio, minRatio, up, down)
	}
	t.Logf("post-H8 sequential OK: up=%.0f down=%.0f ratio=%.2f", up, down, ratio)
}

// TestGATEH2AsymShallowUploadProfileFCNotBottleneck locks shallow-pipe profile: FC waits=0; TLS flush ~½ data frames.
func TestGATEH2AsymShallowUploadProfileFCNotBottleneck(t *testing.T) {
	if masque.ExportConnectStreamH2AsymShallowProfileMaxFCWaits > 0 {
		t.Fatalf("expected waits=0, got %d", masque.ExportConnectStreamH2AsymShallowProfileMaxFCWaits)
	}
	data := masque.ExportConnectStreamH2AsymShallowProfileDataFrames
	flush := masque.ExportConnectStreamH2AsymShallowProfileTLSFlushes
	if data <= 0 || flush <= 0 {
		t.Fatal("shallow profile counters zero")
	}
	if float64(flush)/float64(data) > 0.55 {
		t.Fatalf("TLS flush ratio %.2f too high (data=%d flush=%d)", float64(flush)/float64(data), data, flush)
	}
	t.Logf("shallow profile: data_frames=%d tls_flush=%d ratio=%.2f waits=0", data, flush, float64(flush)/float64(data))
}

// TestGATEH2AsymHypothesisNoBlockingReadFlushDockerIncompatible locks wave-4 H11: breaks upload path.
func TestGATEH2AsymHypothesisNoBlockingReadFlushDockerIncompatible(t *testing.T) {
	if masque.ExportConnectStreamH2AsymNoBlockingReadFlushUpMbps > 0 {
		t.Fatalf("H11 must stay INCOMPATIBLE (upload=0), got %.0f", masque.ExportConnectStreamH2AsymNoBlockingReadFlushUpMbps)
	}
	t.Log("H11 INCOMPATIBLE: skip flush-before-blocking-read breaks H2 CONNECT-stream upload")
}

// TestGATEH2AsymShallowPipeProdDefault locks prod CONNECT-stream upload pipe = 128 KiB.
func TestGATEH2AsymShallowPipeProdDefault(t *testing.T) {
	r, w := h2.NewConnectUploadPipe()
	capFn, ok := r.(interface{ UploadPipeCap() int })
	if !ok {
		t.Fatal("upload pipe reader must implement UploadPipeCap")
	}
	want := h2.ConnectUploadShallowPipeBuf()
	if cap := capFn.UploadPipeCap(); cap != want {
		t.Fatalf("prod pipe cap=%d want=%d", cap, want)
	}
	_ = w.Close()
	_ = r.Close()
}

// TestGATEH2AsymHypothesisBidiPokeOffDockerFalsified locks wave-3 H9: removing bidi poke/bootstrap hurts upload slightly.
// Value: keep bidi poke; not an unproductive divergence to remove.
func TestGATEH2AsymHypothesisBidiPokeOffDockerFalsified(t *testing.T) {
	assertHypothesisFalsified(t, "H9-BIDI-POKE-OFF",
		masque.ExportConnectStreamH2AsymDockerBaselineUpMbps,
		masque.ExportConnectStreamH2AsymBidiPokeOffBisectUpMbps)
}

// TestGATEH2AsymUploadProfileFCNotBottleneck locks upload-only profile: awaitFlowControl waits=0 at prod ceiling.
// Value: asymmetry is not server WINDOW_UPDATE starvation on isolated upload leg.
func TestGATEH2AsymUploadProfileFCNotBottleneck(t *testing.T) {
	maxWaits := masque.ExportConnectStreamH2AsymUploadProfileMaxFCWaits
	if maxWaits > 0 {
		t.Fatalf("expected awaitFlowControl waits=0 at upload ceiling, got %d — update profile ledger", maxWaits)
	}
	t.Log("upload-only profile: awaitFlowControl waits=0 — FC not upload bottleneck (see STR-P2-H2-UPLOAD-ASYM-HYPOTHESES.md)")
}

// TestGATEH2AsymBottleneckIsClientUpload locks localization: upload path is client-primary, not server relay.
// Value: prevents server-relay rewrites as the default fix path (see STR-P2-H2-UPLOAD-ASYM-H2O-COMPARE.md).
func TestGATEH2AsymBottleneckIsClientUpload(t *testing.T) {
	up := masque.ExportConnectStreamH2AsymDockerBaselineUpMbps
	down := masque.ExportConnectStreamH2AsymDockerBaselineDownMbps
	upOnly := masque.ExportConnectStreamH2AsymUploadOnlyMbps
	h3Up := masque.ExportConnectStreamH2AsymH3ControlUpMbps
	h3Down := masque.ExportConnectStreamH2AsymH3ControlDownMbps
	if down <= 0 || up <= 0 {
		t.Fatal("baseline legs zero")
	}
	if up/down >= 0.85 {
		t.Fatalf("baseline already symmetric (%.2f) — update ledger", up/down)
	}
	// Upload-only must not be materially faster than sequential upload (server/session pollution ruled out).
	if hypothesisUplift(up, upOnly) > masque.ExportConnectStreamH2AsymHypothesisMinUplift {
		t.Fatalf("upload-only uplift %.1f%% suggests ordering/server pollution — re-open H4",
			hypothesisUplift(up, upOnly)*100)
	}
	// H3 control must stay near-symmetric (harness + server onward OK).
	h3Ratio := h3Up / h3Down
	if h3Ratio > h3Down/h3Up {
		h3Ratio = h3Down / h3Up
	}
	if h3Ratio < masque.ExportConnectStreamH2AsymH3ControlMinRatio {
		t.Fatalf("H3 control not symmetric (%.2f) — cannot blame H2 client alone", h3Ratio)
	}
	t.Logf("bottleneck=CLIENT H2 upload: baseline up/down=%.2f upload_only=%.0f H3 ratio=%.2f",
		up/down, upOnly, h3Ratio)
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

func assertHypothesisConfirmed(t *testing.T, id string, baseUp, bisectUp float64) {
	t.Helper()
	uplift := hypothesisUplift(baseUp, bisectUp)
	minUplift := masque.ExportConnectStreamH2AsymHypothesisMinUplift
	if uplift <= minUplift {
		t.Fatalf("%s FALSIFIED upload uplift %.1f%% <= %.0f%% — update ledger (base=%.0f bisect=%.0f)",
			id, uplift*100, minUplift*100, baseUp, bisectUp)
	}
	t.Logf("%s CONFIRMED: Docker upload %.0f→%.0f Mbit/s (%.1f%% uplift vs baseline)",
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

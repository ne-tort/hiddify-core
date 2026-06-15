package masque

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/h3"
)

// TestREFSegmentMatrix runs paired ref vs prod segment comparisons and layer ceilings.
func TestREFSegmentMatrix(t *testing.T) {
	const d = refBenchDuration

	t.Run("mock-pairs", func(t *testing.T) {
		var prodRows, refRows []refBenchResult
		pairs := []refProdPair{
			{
				ID: "inv-mock-download", Shape: "mock", Leg: "download",
				RefMbps:  func(t *testing.T) float64 { return benchRefInvisvDownloadMbps(d) },
				ProdMbps: func(t *testing.T) float64 { return h3.ExportBenchProdTunnelConnDownloadMbps(d) },
				RefFloor: refSynthInstantLinkCeilingMbps, ProdFloor: refSynthInstantLinkCeilingMbps,
			},
			{
				ID: "inv-mock-upload", Shape: "mock", Leg: "upload",
				RefMbps:  func(t *testing.T) float64 { return benchRefInvisvUploadMbps(d) },
				ProdMbps: func(t *testing.T) float64 { return h3.ExportBenchProdTunnelConnUploadMbps(d) },
				RefFloor: refSynthInstantLinkCeilingMbps, ProdFloor: refSynthInstantLinkCeilingMbps,
			},
			{
				ID: "inv-mock-duplex-min", Shape: "mock", Leg: "duplex",
				RefMbps:  func(t *testing.T) float64 { return benchRefInvisvDuplexMinMbps(d) },
				ProdMbps: func(t *testing.T) float64 { return benchProdTunnelConnMockDuplexMinMbps(d) },
				RefFloor: refSynthInstantLinkCeilingMbps, ProdFloor: refSynthInProcStackFloorMbps,
			},
		}
		for _, p := range pairs {
			refRows = append(refRows, refBenchResult{ID: p.ID, Shape: p.Shape, Leg: p.Leg, Mbps: p.RefMbps(t)})
			prodRows = append(prodRows, assertRefProdDelta(t, p))
		}
		logRefDeltaTable(t, prodRows, refRows)
	})

	t.Run("H3-L1-ceiling", func(t *testing.T) {
		h3L1 := benchConnectStreamDownloadLayerWriteTo(t, "L1", instantBidiLink{}, d)
		if h3L1.err != nil {
			t.Fatalf("H3 L1 download: %v", h3L1.err)
		}
		t.Logf("layer H3-L1 instant download: %.1f Mbit/s", h3L1.mbps)
		if h3L1.mbps < refSynthH3QUICInstantCeilingMbps {
			t.Fatalf("H3 L1 instant download %.1f Mbit/s (want >= %.0f QUIC synth ceiling)",
				h3L1.mbps, refSynthH3QUICInstantCeilingMbps)
		}
	})

	t.Run("H2-H3-L1-ratio", func(t *testing.T) {
		h3L1 := benchConnectStreamDownloadLayerWriteTo(t, "L1", instantBidiLink{}, d)
		if h3L1.err != nil {
			t.Fatalf("H3 L1 download: %v", h3L1.err)
		}
		h2L1 := benchConnectStreamH2DownloadLayerWriteTo(t, "L1", instantBidiLink{}, d)
		if h2L1.err != nil {
			t.Fatalf("H2 L1 download: %v", h2L1.err)
		}
		ratio := h3L1.mbps / h2L1.mbps
		t.Logf("H3-L1=%.1f H2-L1=%.1f ratio=%.3f (want >= %.2f)", h3L1.mbps, h2L1.mbps, ratio, connectStreamSynthParityMinRatio)
		if ratio < connectStreamSynthParityMinRatio {
			t.Fatalf("H3/H2 L1 download ratio %.3f: H3=%.1f H2=%.1f", ratio, h3L1.mbps, h2L1.mbps)
		}
	})

	t.Run("h2o-relay-ref", func(t *testing.T) {
		t.Setenv("MASQUE_RELAY_TCP_BATCHED_DUPLEX_WAKE", "0")
		t.Setenv("MASQUE_RELAY_TCP_SKIP_PRIME", "1")
		t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "1")
		_, refH2oMbps := benchRefH2oRelayDownloadMbps(t, d)
		t.Logf("layer h2o-relay ref: %.1f Mbit/s", refH2oMbps)
		if refH2oMbps < refSynthInstantLinkCeilingMbps {
			t.Fatalf("REF-h2o relay %.1f < ceiling %.0f", refH2oMbps, refSynthInstantLinkCeilingMbps)
		}
	})

	t.Run("h2o-relay-prod-vs-ref", func(t *testing.T) {
		_, refMbps := benchRefH2oRelayDownloadMbps(t, d)
		_, prodMbps := benchProdH2oEnvRelayDownloadMbps(t, d)
		t.Logf("h2o-relay ref=%.1f prod=%.1f ratio=%.2f", refMbps, prodMbps, prodMbps/refMbps)
		if prodMbps < refMbps*0.85 {
			t.Fatalf("prod relay %.1f < 85%% of h2o ref %.1f — server path diverged", prodMbps, refMbps)
		}
	})
}

// TestREFSegmentMatrixLegsVsDuplex localizes saturated duplex vs single-leg ceilings on prod stack.
func TestREFSegmentMatrixLegsVsDuplex(t *testing.T) {
	const d = localizeBenchDuration
	link := instantBidiLink{}

	downH := startConnectStreamDownloadHarness(t, link)
	defer downH.close()
	_, downLeg, err := measureTCPDownloadWriteToMbps(downH.conn, d)
	if err != nil {
		t.Fatalf("download leg: %v", err)
	}

	upH := startConnectStreamDownloadHarness(t, link)
	defer upH.close()
	_, upLeg, err := measureTCPUploadMbps(upH.conn, d)
	if err != nil {
		t.Fatalf("upload leg: %v", err)
	}

	dupH := startConnectStreamDownloadHarness(t, link)
	defer dupH.close()
	dupDown, dupUp, dupMin, err := measureSegmentDuplexMbps(dupH.conn, d)
	if err != nil {
		t.Fatalf("duplex: %v", err)
	}

	t.Logf("legs down=%.1f up=%.1f | duplex down=%.1f up=%.1f min=%.1f | duplex/leg down=%.2f",
		downLeg, upLeg, dupDown, dupUp, dupMin, dupDown/downLeg)

	if downLeg < refSynthInProcStackFloorMbps {
		t.Fatalf("download leg %.1f < %.0f", downLeg, refSynthInProcStackFloorMbps)
	}
	if dupMin < refSynthInProcStackFloorMbps {
		t.Fatalf("duplex min %.1f < %.0f DoD", dupMin, refSynthInProcStackFloorMbps)
	}
}

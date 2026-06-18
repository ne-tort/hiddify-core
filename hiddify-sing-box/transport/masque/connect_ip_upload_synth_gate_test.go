package masque

import "testing"

// TestGATEConnectIPUploadSynth is the in-proc upload localization gate (pipe, no QUIC).
// Run this (+ TestGATEConnectIPUploadSynthNative) before Docker connect-ip-h3-tun.
func TestGATEConnectIPUploadSynth(t *testing.T) {
	const duration = localizeBenchDuration

	l0 := benchConnectIPUploadLayer(t, "L0", nil, duration)
	l1 := benchConnectIPUploadLayer(t, "L1", instantPacketLink{}, duration)
	l3 := benchConnectIPUploadLayer(t, "L3", benchWindowedPacketLink(), duration)

	for _, r := range []connectIPUploadBenchResult{l0, l1, l3} {
		if !r.ok() {
			t.Fatalf("%s: %v", r.layer, r.err)
		}
		t.Logf("upload %s: %.1f Mbit/s (%d bytes)", r.layer, r.mbps, r.bytes)
	}

	if l0.mbps < connectIPLocalizeFastMbps {
		t.Fatalf("L0 loopback slow: %.1f Mbit/s (host sanity)", l0.mbps)
	}
	if l1.mbps < connectIPSynthRegressionFloorUpMbps {
		t.Fatalf("pipe L1 upload regression: %.1f < %.1f Mbit/s — fix forwarder/netstack before QUIC",
			l1.mbps, connectIPSynthRegressionFloorUpMbps)
	}
	if l3.mbps < connectIPLocalizeCeilingMin || l3.mbps > connectIPLocalizeCeilingMax {
		t.Fatalf("pipe L3 windowed upload: %.1f Mbit/s (want %.0f–%.0f — harness calibration)",
			l3.mbps, connectIPLocalizeCeilingMin, connectIPLocalizeCeilingMax)
	}

	t.Logf("GATE-CONNECT-IP-UPLOAD pipe verdict: %s", verdictConnectIPUpload(l0, l1, l3))
	if l1.mbps < connectIPSynthProdMinMbps {
		t.Logf("OPEN: pipe L1 upload %.1f < DoD %.0f (expected until forwarder path raised)",
			l1.mbps, connectIPSynthProdMinMbps)
	}
}

// TestGATEConnectIPUploadSynthDockerProxy mirrors docker tcp_up/tcp_down KPI without containers
// (instant pipe = forwarder + gVisor only).
func TestGATEConnectIPUploadSynthDockerProxy(t *testing.T) {
	t.Run("upload", func(t *testing.T) {
		h := startConnectIPUploadHarness(t, instantPacketLink{})
		defer h.close()
		conn := h.dialRemote(t)
		defer conn.Close()
		bytes, mbps, err := measureTCPUploadMbps(conn, localizeBenchDuration)
		if err != nil {
			t.Fatalf("upload: %v", err)
		}
		t.Logf("docker KPI proxy upload: %.1f Mbit/s (%d B)", mbps, bytes)
		if mbps < connectIPSynthRegressionFloorUpMbps {
			t.Fatalf("upload %.1f < regression floor %.1f", mbps, connectIPSynthRegressionFloorUpMbps)
		}
	})

	t.Run("download", func(t *testing.T) {
		h := startConnectIPDownloadHarness(t, instantPacketLink{})
		defer h.close()
		conn := h.dialRemote(t)
		defer conn.Close()
		bytes, mbps, err := measureTCPDownloadMbps(conn, localizeBenchDuration)
		if err != nil {
			t.Fatalf("download: %v", err)
		}
		t.Logf("docker KPI proxy download: %.1f Mbit/s (%d B)", mbps, bytes)
		if mbps < connectIPSynthRegressionFloorUpMbps {
			t.Fatalf("download %.1f < regression floor %.1f", mbps, connectIPSynthRegressionFloorUpMbps)
		}
	})
}

package masque

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/h3"
)

// Arch investigation synth guards (ARCH-INVESTIGATION wave A2).
// KPI anchors: K-S1/K-S2 windowed WriteTo ~15.7; P1 breaks app-level bidi contention, not wire FC.

// TestArchBidiContentionReproducesCeiling (A2-1): windowed bidi WriteTo stays in credit/RTT band.
func TestArchBidiContentionReproducesCeiling(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")

	r := benchConnectStreamDownloadLayerWriteTo(t, "L3", benchWindowedBidiLink(), localizeBenchDuration)
	if r.err != nil {
		t.Fatalf("windowed WriteTo: %v", r.err)
	}
	t.Logf("A2-1 bidi windowed WriteTo: %.1f Mbit/s", r.mbps)
	assertConnectStreamWindowedCeilingBand(t, r.mbps, "A2-1 bidi contention ceiling")
}

// TestArchPipeUploadDecouplesCeiling (A2-2): pipe upload on instant link exceeds VPS KPI;
// bidi duplex on windowed link stays in ceiling band.
func TestArchPipeUploadDecouplesCeiling(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")

	hBidi := startConnectStreamDownloadHarness(t, benchWindowedBidiLink())
	defer hBidi.close()
	bidi := runConnectStreamDuplexWriteToBenchOnConn(t, hBidi.conn, connectStreamLocalizeDownloadKPIMin/2)
	assertConnectStreamWindowedCeilingBand(t, bidi.mbps, "A2-2 bidi duplex windowed")

	hPipe := startConnectStreamDownloadHarness(t, instantBidiLink{}, connectStreamHarnessOpts{PipeUpload: true})
	defer hPipe.close()
	pipe := runConnectStreamDuplexWriteToBenchOnConn(t, hPipe.conn, connectStreamVPSKPITargetDownMbps)
	if pipe.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("A2-2 pipe instant duplex: %.1f Mbit/s (want > %.0f)", pipe.mbps, connectStreamVPSKPITargetDownMbps)
	}
	t.Logf("A2-2 pipe instant duplex: %.1f Mbit/s", pipe.mbps)
}

// TestArchPipeUploadWindowedLink (A2-2a): P1 go/no-go under wire FC — pipe decouples app path but
// per-direction S2C credit still caps download at ~64 KiB/RTT (~15.7 Mbit/s).
func TestArchPipeUploadWindowedLink(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")

	t.Run("download_only_wire_fc_ceiling", func(t *testing.T) {
		h := startConnectStreamDownloadHarness(t, benchWindowedBidiLink(), connectStreamHarnessOpts{PipeUpload: true})
		defer h.close()
		n, mbps, err := measureTCPDownloadWriteToMbps(h.conn, localizeBenchDuration)
		if err != nil {
			t.Fatalf("pipe windowed download-only: %v", err)
		}
		t.Logf("A2-2a pipe windowed download-only: %.1f Mbit/s (%d bytes)", mbps, n)
		assertConnectStreamWindowedCeilingBand(t, mbps, "A2-2a pipe windowed download-only")
	})

	t.Run("duplex_not_worse_than_download_only", func(t *testing.T) {
		hOnly := startConnectStreamDownloadHarness(t, benchWindowedBidiLink(), connectStreamHarnessOpts{PipeUpload: true})
		defer hOnly.close()
		n, dlOnlyMbps, err := measureTCPDownloadWriteToMbps(hOnly.conn, localizeBenchDuration)
		if err != nil {
			t.Fatalf("pipe windowed download-only: %v", err)
		}
		h := startConnectStreamDownloadHarness(t, benchWindowedBidiLink(), connectStreamHarnessOpts{PipeUpload: true})
		defer h.close()
		duplex := runConnectStreamDuplexWriteToBenchOnConn(t, h.conn, connectStreamLocalizeDownloadKPIMin/2)
		t.Logf("A2-2a pipe windowed download-only=%.1f duplex=%.1f Mbit/s (%d bytes)", dlOnlyMbps, duplex.mbps, n)
		assertConnectStreamWindowedCeilingBand(t, dlOnlyMbps, "A2-2a pipe windowed download-only")
		assertConnectStreamWindowedCeilingBand(t, duplex.mbps, "A2-2a pipe windowed duplex")
		// Concurrent upload pulse contends with download on windowed link — both legs must meet KPI.
	})
}

// TestArchDuplexUploadPulseKillsDownload (A2-3): upload pulse on bidi windowed caps download in ceiling band.
func TestArchDuplexUploadPulseKillsDownload(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")

	dlOnly := benchConnectStreamDownloadLayerWriteTo(t, "L3", benchWindowedBidiLink(), localizeBenchDuration)
	duplex := runConnectStreamDuplexWriteToBench(t, benchWindowedBidiLink(), connectStreamLocalizeDownloadKPIMin/2)
	t.Logf("A2-3 download-only=%.1f duplex=%.1f Mbit/s", dlOnly.mbps, duplex.mbps)
	assertConnectStreamWindowedCeilingBand(t, duplex.mbps, "A2-3 bidi duplex under pulse")
	if duplex.mbps > dlOnly.mbps+2 {
		t.Fatalf("duplex %.1f unexpectedly above download-only %.1f — pulse should not improve bidi ceiling", duplex.mbps, dlOnly.mbps)
	}
}

// TestArchBidiWindowModelsCeiling (A2-7): WrapBidiWindow WriteTo reproduces 4–28 Mbit/s band.
func TestArchBidiWindowModelsCeiling(t *testing.T) {
	r := benchConnectStreamDownloadLayerWriteTo(t, "L3", benchWindowedBidiLink(), localizeBenchDuration)
	if r.err != nil {
		t.Fatalf("windowed WriteTo: %v", r.err)
	}
	t.Logf("A2-7 window model: %.1f Mbit/s", r.mbps)
	assertConnectStreamWindowedCeilingBand(t, r.mbps, "A2-7 WrapBidiWindow ceiling")
}

// TestArchP1WindowedWriteToKS1 (A2-8): P1 download-only on windowed link — wire FC band (K-S1 still OPEN).
func TestArchP1WindowedWriteToKS1(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")

	h := startConnectStreamDownloadHarness(t, benchWindowedBidiLink(), connectStreamHarnessOpts{PipeUpload: true})
	defer h.close()
	tc, ok := unwrapH3TunnelConn(h.conn)
	if !ok || tc.UsesH3Stream() {
		t.Fatal("P1 path must use pipe upload (UsesH3Stream=false)")
	}
	n, mbps, err := measureTCPDownloadWriteToMbps(h.conn, localizeBenchDuration)
	if err != nil {
		t.Fatalf("P1 windowed WriteTo: %v", err)
	}
	if n < localizeBenchMinBytes {
		t.Fatalf("bytes=%d want >= %d", n, localizeBenchMinBytes)
	}
	t.Logf("A2-8 P1 windowed download-only: %.1f Mbit/s (K-S1 >21 needs P2 or credit fix)", mbps)
	assertConnectStreamWindowedCeilingBand(t, mbps, "A2-8 P1 K-S1 wire FC band")
}

// TestArchP1DuplexWriteToKS2 (A2-9): P1 instant duplex >21; windowed duplex stays in FC band (K-S2 OPEN on L3).
func TestArchP1DuplexWriteToKS2(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")

	t.Run("instant_exceeds_vps_kpi", func(t *testing.T) {
		h := startConnectStreamDownloadHarness(t, instantBidiLink{}, connectStreamHarnessOpts{PipeUpload: true})
		defer h.close()
		dl := runConnectStreamDuplexWriteToBenchOnConn(t, h.conn, connectStreamVPSKPITargetDownMbps)
		t.Logf("A2-9 P1 instant duplex: %.1f Mbit/s", dl.mbps)
	})

	t.Run("windowed_wire_fc_band", func(t *testing.T) {
		h := startConnectStreamDownloadHarness(t, benchWindowedBidiLink(), connectStreamHarnessOpts{PipeUpload: true})
		defer h.close()
		dl := runConnectStreamDuplexWriteToBenchOnConn(t, h.conn, connectStreamLocalizeDownloadKPIMin/2)
		assertConnectStreamWindowedCeilingBand(t, dl.mbps, "A2-9 P1 windowed duplex")
		t.Logf("A2-9 P1 windowed duplex: %.1f Mbit/s (K-S2 >21 blocked by wire FC — escalate P2)", dl.mbps)
	})
}

// TestArchREFSRCProdDefaultH3Stream (REF-SRC-SB-C2): prod dial uses h3_stream unless explicit pipe opt-in.
func TestArchREFSRCProdDefaultH3Stream(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_STREAM_PIPE_UPLOAD", "")
	t.Setenv("MASQUE_CONNECT_STREAM_H3_STREAM", "")
	t.Setenv("MASQUE_CONNECT_STREAM_DUAL_CONNECT", "")
	if h3.ConnectStreamUsePipeUpload() {
		t.Fatal("expected h3_stream prod default (pipe off)")
	}
	t.Setenv("MASQUE_CONNECT_STREAM_PIPE_UPLOAD", "1")
	if !h3.ConnectStreamUsePipeUpload() {
		t.Fatal("expected legacy pipe with MASQUE_CONNECT_STREAM_PIPE_UPLOAD=1")
	}
}

// TestArchPostA3PatternGuard (A2-4): prod h3_stream windowed WriteTo exceeds KPI on unified harness.
func TestArchPostA3PatternGuard(t *testing.T) {
	h := startConnectStreamDownloadHarness(t, benchWindowedBidiLink())
	defer h.close()
	_, dlMbps, err := measureTCPDownloadWriteToMbps(h.conn, localizeBenchDuration)
	if err != nil {
		t.Fatalf("windowed download-only: %v", err)
	}
	duplex := runConnectStreamDuplexWriteToBench(t, benchWindowedBidiLink(), connectStreamLocalizeDownloadKPIMin/2)
	if dlMbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("K-S1: %.1f Mbit/s want > %.0f", dlMbps, connectStreamVPSKPITargetDownMbps)
	}
	if duplex.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("K-S2: %.1f Mbit/s want > %.0f", duplex.mbps, connectStreamVPSKPITargetDownMbps)
	}
	t.Logf("post-A3 prod verdict: download=%.1f duplex=%.1f Mbit/s", dlMbps, duplex.mbps)
}

// TestArchA4P8L256WindowedWriteToKS1 (A4-1/P8): P1 + 256 KiB bench FC exceeds K-S1 VPS KPI.
// L3 64 KiB ceiling band stays a separate regression guard (field symptom model).
func TestArchA4P8L256WindowedWriteToKS1(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")

	h := startConnectStreamDownloadHarness(t, benchWindowedBidiLinkL256(), connectStreamHarnessOpts{PipeUpload: true})
	defer h.close()
	tc, ok := unwrapH3TunnelConn(h.conn)
	if !ok || tc.UsesH3Stream() {
		t.Fatal("P1 path must use pipe upload (UsesH3Stream=false)")
	}
	n, mbps, err := measureTCPDownloadWriteToMbps(h.conn, localizeBenchDuration)
	if err != nil {
		t.Fatalf("P8 L256 windowed WriteTo: %v", err)
	}
	if n < localizeBenchMinBytes {
		t.Fatalf("bytes=%d want >= %d", n, localizeBenchMinBytes)
	}
	t.Logf("A4 P8 L256 windowed download-only: %.1f Mbit/s (K-S1 >21 via bulk FC floor)", mbps)
	if mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("P8 L256 %.1f Mbit/s (want > %.0f)", mbps, connectStreamVPSKPITargetDownMbps)
	}
}

// TestArchA4P8L256DuplexWriteToKS2 (A4-2/P8): P1 duplex on L256 bench FC exceeds K-S2 VPS KPI.
func TestArchA4P8L256DuplexWriteToKS2(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")

	h := startConnectStreamDownloadHarness(t, benchWindowedBidiLinkL256(), connectStreamHarnessOpts{PipeUpload: true})
	defer h.close()
	dl := runConnectStreamDuplexWriteToBenchOnConn(t, h.conn, connectStreamVPSKPITargetDownMbps)
	t.Logf("A4 P8 L256 duplex WriteTo: %.1f Mbit/s", dl.mbps)
	if dl.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("P8 L256 duplex %.1f Mbit/s (want > %.0f)", dl.mbps, connectStreamVPSKPITargetDownMbps)
	}
}

// TestArchA4AcceptanceVerdict (A4-1/A4-2): P1+P8 bulk FC floor exceeds K-S1/K-S2 VPS KPI on L256 harness.
// L3 64 KiB/RTT symptom (~15.7) is a separate field-model guard (A2-8/A2-9), not prod acceptance.
func TestArchA4AcceptanceVerdict(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")

	var verdict ArchA4AcceptanceVerdict

	hDL := startConnectStreamDownloadHarness(t, benchWindowedBidiLinkL256(), connectStreamHarnessOpts{PipeUpload: true})
	defer hDL.close()
	_, verdict.P8L256DownloadMbps, _ = measureTCPDownloadWriteToMbps(hDL.conn, localizeBenchDuration)

	hDup := startConnectStreamDownloadHarness(t, benchWindowedBidiLinkL256(), connectStreamHarnessOpts{PipeUpload: true})
	defer hDup.close()
	duplex := runConnectStreamDuplexWriteToBenchOnConn(t, hDup.conn, connectStreamVPSKPITargetDownMbps)
	verdict.P8L256DuplexMbps = duplex.mbps

	t.Logf("A4 acceptance: P8 L256 download=%.1f duplex=%.1f Mbit/s (K-S target >%.0f)",
		verdict.P8L256DownloadMbps, verdict.P8L256DuplexMbps, connectStreamVPSKPITargetDownMbps)
	if !verdict.KS1Accepted() || !verdict.KS2Accepted() {
		t.Fatalf("A4 K-S acceptance failed: KS1=%v (%.1f) KS2=%v (%.1f)",
			verdict.KS1Accepted(), verdict.P8L256DownloadMbps,
			verdict.KS2Accepted(), verdict.P8L256DuplexMbps)
	}
}

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

// TestArchPipeUploadDecouplesCeiling removed — pipe upload path cut from prod.
func TestArchPipeUploadDecouplesCeiling(t *testing.T) {
	t.Skip("P1 pipe upload removed — prod is single-bidi Invisv path")
}

func TestArchPipeUploadWindowedLink(t *testing.T) {
	t.Skip("P1 pipe upload removed — prod is single-bidi Invisv path")
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

func TestArchP1WindowedWriteToKS1(t *testing.T) {
	t.Skip("P1 pipe upload removed — prod is single-bidi Invisv path")
}

func TestArchP1DuplexWriteToKS2(t *testing.T) {
	t.Skip("P1 pipe upload removed — prod is single-bidi Invisv path")
}

// TestArchREFSRCProdDefaultH3Stream (REF-SRC-SB-C2): prod dial is single-bidi Invisv (nil Body).
func TestArchREFSRCProdDefaultH3Stream(t *testing.T) {
	if h3.CurrentConnectStreamMode() != h3.ConnectStreamModeSingleBidi {
		t.Fatalf("expected single_bidi mode, got %q", h3.CurrentConnectStreamMode())
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

func TestArchA4P8L256WindowedWriteToKS1(t *testing.T) {
	t.Skip("P1 pipe upload removed — prod is single-bidi Invisv path")
}

func TestArchA4P8L256DuplexWriteToKS2(t *testing.T) {
	t.Skip("P1 pipe upload removed — prod is single-bidi Invisv path")
}

func TestArchA4AcceptanceVerdict(t *testing.T) {
	t.Skip("P1 pipe upload removed — prod is single-bidi Invisv path")
}

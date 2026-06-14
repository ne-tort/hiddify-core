package masque

import (
	"fmt"
	"time"
)

// connectStreamVPSKPITargetDownMbps matches field invoke.py BENCH_KPI_DOWN_MBIT (K-S1/K-S2 weak floor only).
const connectStreamVPSKPITargetDownMbps = 21.0

// GATE-H3-SYNTH / H2 anchor — prod stack in-proc (LaunchMasqueStack + SOCKS/CM, no artificial window wrap).
const (
	connectStreamSynthProdMinMbps      = 200.0 // min(up, down) target; satisfactory ≈ H2 synth
	connectStreamSynthParityMinRatio   = 0.85  // H3/H2 on paired gate (H3 not >15% behind H2)
	connectStreamSynthDuplexMaxRatio   = 4.0   // max(up,down)/min(up,down) on concurrent duplex
	connectStreamSynthProdBenchDuration = 2 * time.Second
)

// GATE-CONNECT-UDP-SYNTH — prod profile in-proc (transport_mode=connect_udp); UDP KPI ≠ TCP connect_stream.
const (
	connectUDPSynthProdBurstMinMbps     = 40.0 // unlimited sender on instant link (localize burst floor)
	connectUDPSynthParityMinRatio       = 0.85 // H3/H2 burst paired gate
	connectUDPSynthInProcPacedMinMbps   = 3.5  // in-proc band @ 8 Mbit/s target (not docker WAN ~6.75)
	connectUDPSynthInProcPacedMaxMbps   = 5.5
	connectUDPSynthProdBenchDuration    = 2 * time.Second
)

// synthKPIDiagnostic formats a FAIL message naming layer, leg, got/want Mbps, optional hint.
func synthKPIDiagnostic(layer, leg string, gotMbps, wantMbps float64, hint string) string {
	msg := layer + " " + leg + ": " +
		formatSynthMbps(gotMbps) + " Mbit/s (want >= " + formatSynthMbps(wantMbps) + " Mbit/s)"
	if hint != "" {
		msg += "; " + hint
	}
	return msg
}

func formatSynthMbps(v float64) string {
	return fmt.Sprintf("%.1f", v)
}

// ArchPatternGuardVerdict captures post-A3 synth measurements for K-S1/K-S2 windowed WriteTo.
// KS1/KS2 exceed VPS KPI (>21 Mbit/s) when wire FC ceiling is broken; until then they stay OPEN.
type ArchPatternGuardVerdict struct {
	P1WindowedDownloadMbps float64
	P1WindowedDuplexMbps   float64
	P2WindowedDownloadMbps float64
	P2WindowedDuplexMbps   float64
}

// ArchA4AcceptanceVerdict captures P8+L256 acceptance for K-S1/K-S2 (>21 Mbit/s).
// L3 64 KiB field symptom stays guarded separately (A2-8/A2-9 ceiling band).
type ArchA4AcceptanceVerdict struct {
	P8L256DownloadMbps float64
	P8L256DuplexMbps   float64
}

// KS1Accepted reports K-S1 >21 via P8 bulk FC floor (L256 harness or prod QUIC windows).
func (v ArchA4AcceptanceVerdict) KS1Accepted() bool {
	return v.P8L256DownloadMbps > connectStreamVPSKPITargetDownMbps
}

// KS2Accepted reports K-S2 >21 via P8 bulk FC floor with upload pulse.
func (v ArchA4AcceptanceVerdict) KS2Accepted() bool {
	return v.P8L256DuplexMbps > connectStreamVPSKPITargetDownMbps
}

// KS1Open reports whether windowed download-only WriteTo still misses the >21 Mbit/s KPI.
func (v ArchPatternGuardVerdict) KS1Open() bool {
	return v.P1WindowedDownloadMbps <= connectStreamVPSKPITargetDownMbps &&
		v.P2WindowedDownloadMbps <= connectStreamVPSKPITargetDownMbps
}

// KS2Open reports whether windowed duplex WriteTo still misses the >21 Mbit/s KPI.
func (v ArchPatternGuardVerdict) KS2Open() bool {
	return v.P1WindowedDuplexMbps <= connectStreamVPSKPITargetDownMbps &&
		v.P2WindowedDuplexMbps <= connectStreamVPSKPITargetDownMbps
}

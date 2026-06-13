package masque

// connectStreamVPSKPITargetDownMbps matches field invoke.py BENCH_KPI_DOWN_MBIT (K-S1/K-S2 acceptance).
const connectStreamVPSKPITargetDownMbps = 21.0

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

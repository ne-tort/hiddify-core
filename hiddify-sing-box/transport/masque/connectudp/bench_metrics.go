package connectudp

// Paced goodput calibration @ netem 35 ms (docs/masque/benchmark-matrix.md § Paced goodput).
// Efficiency with compensated pacing (slot += interval); legacy sleep-after-send was ~0.84.
const (
	pacedGoodputEfficiency = 0.97
	pacedGoodputFloorRatio = 0.90
)

// ExpectedPacedGoodputMbit returns the typical sink goodput for a paced sender target (Mbit/s).
func ExpectedPacedGoodputMbit(targetMbit float64) float64 {
	if targetMbit <= 0 {
		return 0
	}
	return targetMbit * pacedGoodputEfficiency
}

// MinPacedGoodputMbit returns the KPI floor (target × 0.90) for paced UDP probe gates.
func MinPacedGoodputMbit(targetMbit float64) float64 {
	if targetMbit <= 0 {
		return 0
	}
	return targetMbit * pacedGoodputFloorRatio
}

// BurstSinkGoodputMbit returns sink goodput (Mbit/s) from sequenced rx count and wall seconds.
// Parity docker/masque-perf-lab _direct_burst.py: rx_pkts × payload × 8 / send_sec.
func BurstSinkGoodputMbit(rxPkts, payloadLen int, wallSec float64) float64 {
	if wallSec <= 0 || rxPkts <= 0 || payloadLen <= 0 {
		return 0
	}
	return float64(rxPkts*payloadLen*8) / wallSec / 1e6
}

// Observed max burst ceiling (informational; docker @ netem 35 ms, docs/masque/benchmark-matrix.md).
const (
	ObservedMaxBurstLossPct   = 86.0
	ObservedMaxBurstMbit      = 123.25
	ObservedMaxBurstH2LossPct = 87.4
	ObservedMaxBurstH2Mbit    = 116.31
)

package connectudp

import "time"

// DefaultBenchUDPPayloadLen matches docker/masque-perf-lab BENCH_UDP_PAYLOAD_LEN.
const DefaultBenchUDPPayloadLen = 512

// DefaultBenchNetemDelayMS matches docker/masque-perf-lab BENCH_NETEM_DELAY_MS default.
const DefaultBenchNetemDelayMS = 35

// DefaultBenchUDPTargetMbit matches docker/masque-perf-lab BENCH_UDP_TARGET_MBIT default (legacy paced probe).
// GATE-CONNECT-UDP-SYNTH DoD: unlimited up/down >= 200 Mbit/s (Docker final), synth instant link >= 500 Mbit/s.
const DefaultBenchUDPTargetMbit = 8.0

// ObservedPacedGoodputEfficiency is measured goodput / target at netem 35 ms (bench-history 2026-05-19: ~6.75/8).
const ObservedPacedGoodputEfficiency = 0.84375

// DockerPacedUDPMinUpMbit is the paced KPI floor in run_local.py (BENCH_UDP_MIN_UP_MBIT).
const DockerPacedUDPMinUpMbit = 6.0

// ObservedMaxBurstLossPct documents connect-udp-h3 unlimited sender loss @ netem 35 ms (informational).
const ObservedMaxBurstLossPct = 86.0

// ObservedMaxBurstMbit documents connect-udp-h3 unlimited sender ceiling @ netem 35 ms (informational).
const ObservedMaxBurstMbit = 123.25

// ObservedMaxBurstRxSentRatio is connect-udp-h3 rx/sent at unlimited rate (informational).
const ObservedMaxBurstRxSentRatio = 0.140

// ObservedMaxBurstH2LossPct documents connect-udp-h2 unlimited sender loss @ netem 35 ms (informational).
const ObservedMaxBurstH2LossPct = 87.36

// ObservedMaxBurstH2Mbit documents connect-udp-h2 unlimited sender ceiling @ netem 35 ms (informational).
const ObservedMaxBurstH2Mbit = 116.31

// ObservedMaxBurstH2RxSentRatio is connect-udp-h2 rx/sent at unlimited rate (informational).
const ObservedMaxBurstH2RxSentRatio = 0.126

// PaceInterval returns the sender sleep between datagrams for targetMbit (>0).
// targetMbit <= 0 means unlimited burst (no pacing), mirroring udp_masque_send.py.
func PaceInterval(payloadLen int, targetMbit float64) time.Duration {
	if targetMbit <= 0 || payloadLen <= 0 {
		return 0
	}
	seconds := float64(payloadLen*8) / (targetMbit * 1_000_000.0)
	return time.Duration(seconds * float64(time.Second))
}

// ExpectedPacedGoodputMbit returns empirically calibrated goodput for targetMbit at DefaultBenchNetemDelayMS.
// Path overhead (MASQUE datagram + SOCKS) dominates; RTT sweep @ 35–70 ms stays within repro tolerance.
func ExpectedPacedGoodputMbit(targetMbit float64) float64 {
	if targetMbit <= 0 {
		return 0
	}
	return targetMbit * ObservedPacedGoodputEfficiency
}

// MinPacedGoodputMbit returns the docker KPI floor for targetMbit (BENCH_UDP_MIN_UP_MBIT scales linearly).
func MinPacedGoodputMbit(targetMbit float64) float64 {
	if targetMbit <= 0 {
		return 0
	}
	return targetMbit * (DockerPacedUDPMinUpMbit / DefaultBenchUDPTargetMbit)
}

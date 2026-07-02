package masque

import (
	"fmt"
	"runtime"
	"time"
)

// connectStreamVPSKPITargetDownMbps matches field invoke.py BENCH_KPI_DOWN_MBIT (K-S1/K-S2 weak floor only).
const connectStreamVPSKPITargetDownMbps = 21.0

// GATE-H3-SYNTH / H2 anchor — prod stack in-proc (LaunchMasqueStack + SOCKS/CM, no artificial window wrap).
const (
	connectStreamSynthProdMinMbps       = 1000.0 // min(up, down) on applicable synth GATE (AGENTS DoD)
	connectStreamSynthParityMinRatio    = 0.85   // H3/H2 on paired gate (H3 not >15% behind H2)
	connectStreamSynthDuplexMaxRatio    = 4.0    // max(up,down)/min(up,down) on concurrent duplex
	connectStreamSynthProdBenchDuration = 2 * time.Second
	connectStreamSynthDuplexGateSamples = 20   // one stack, N dials (not go test -count)
	connectStreamSynthDuplexGateMinPass   = 15   // min PASS samples of GateSamples @1000 each leg
	// connectStreamStrictL256Ceiling35msMbps — theoretical max at L256 wire-FC + 35 ms RTT (localize only).
	connectStreamStrictL256Ceiling35msMbps = 59.0
	connectStreamStrictL256CeilingBandMbps = 52.0
	// connectStreamDocker35msSeq* — perf-lab connect-stream-h3 @35ms netem, sequential iperf legs (localize repro).
	// Обновлять после реального Docker run (не DoD 1000+).
	connectStreamDocker35msSeqDownFloorMbps = 150.0 // stale perf-lab ~224
	connectStreamDocker35msSeqUpFloorMbps   = 50.0  // stale perf-lab ~68
	connectStreamDocker35msSeqMaxRatio      = 4.0
	// connectStreamH2SeqSymmetry* — H2 sequential legs (download-first → fresh upload), parity Docker @0ms.
	// Root cause fixed: upload chunk 4→64 KiB (STR-MS6-P0); ratio was ~7–8× before fix.
	connectStreamH2SeqSymmetryMaxRatio = 2.0 // max(down,up)/min(down,up) after chunk fix
)

// GATE-CONNECT-IP — packet plane (tcp_transport=connect_ip); DoD @ Docker 0ms matches connect-stream (1000+ each leg).
const (
	connectIPSynthProdMinMbps                    = 1000.0 // long-term / Linux in-proc target; Windows native ~165 OPEN
	connectIPSynthRegressionFloorUpMbps          = 80.0   // anti-regression (docker 35ms upload baseline)
	connectIPSynthRegressionFloorDownMbpsLinux   = 280.0  // Linux in-proc native ceiling band
	connectIPSynthRegressionFloorDownMbpsDesktop = 120.0  // Windows/Darwin in-proc QUIC/datagram ceiling band
	connectIPSynthPipeMinRatio                   = 0.45   // native/pipe L1 — forwarder vs QUIC overhead localize
	connectIPSynthPipeFastMinMbps                = 250.0  // pipe L1 fast enough to compare QUIC overhead
	connectIPSynthPipeFastTargetRatio            = 0.85   // OPEN target when pipe >= PipeFastMinMbps
	connectIPSynthPipeFastFloorRatio             = 0.60   // hard fail when pipe fast — raise toward Target as KPI closes
	connectIPSynthWakeEstSegmentBytes            = 1310   // Docker upload wire segment (524 = 50k pps × 1310 B × 8)
	connectIPSynthMaxAsymRatio                   = 8.0
	connectIPSynthProdBenchDuration              = 2 * time.Second
	connectIPDockerProdMinMbps                   = 1000.0 // connect-ip-h3-tun hard gate @0ms netem
	// connectIPDockerStaleUploadMbps — KPI-TRACK 2026-06-17 @0ms connect-ip-h3-tun (Linux Docker).
	connectIPDockerStaleUploadMbps               = 71.0
	connectIPDockerRegressionFloorUpMbps         = 80.0   // @35ms dev regression only
	connectIPDockerRegressionFloorDownMbps       = 350.0
	connectIPDockerMaxAsymRatio                  = 4.0    // WARN when exceeded @0ms
)

// GATE-CONNECT-UDP-SYNTH — prod profile in-proc (transport_mode=connect_udp); same throughput mission as TCP.
const (
	connectUDPSynthProdMinMbps         = 1000.0 // DoD min each leg (up/down)
	connectUDPSynthInstantMinMbps      = 500.0 // synth instant-link GATE (in-proc ceiling target; Linux)
	// connectUDPSynthRegressionFloorDownMbpsDesktop — in-proc fountain S2C anti-regression (Windows QUIC/datagram ceiling ~310–370 observed).
	connectUDPSynthRegressionFloorDownMbpsDesktop = 280.0
	connectUDPSynthInstantGateSlackPct = 0.03  // 3% — Windows in-proc scheduling jitter vs 500 target
	connectUDPSynthAsymmetryMaxRatio   = 4.0   // max(up,down)/min(up,down) on paired legs
	connectUDPSynthParityMinRatio      = 0.75  // H3/H2 paired gate (Windows in-proc variance)
	connectUDPSynthProdBenchDuration   = 2 * time.Second
	// connectUDPSynthMaxLossPct matches docker BENCH_UDP_MAX_LOSS_PCT (paced probe gate).
	connectUDPSynthMaxLossPct          = 5.0
	// connectUDPSynthUploadWriteStall is max wait per WriteTo in stability gates (fail fast, not 60s test timeout).
	connectUDPSynthUploadWriteStall = 750 * time.Millisecond
	// connectUDPSynthStabilityWallSlack is extra wall time allowed beyond bench duration for teardown.
	connectUDPSynthStabilityWallSlack = 1 * time.Second
	// connectUDPSynthGateWaitCtx bounds dial/session setup in synth GATE benches (was 8–30s).
	connectUDPSynthGateWaitCtx = 5 * time.Second
	// connectUDPSynthGateParallelWaitCtx bounds parallel-scaling handle sessions (was 30s).
	connectUDPSynthGateParallelWaitCtx = 12 * time.Second
	// connectUDPSynthGateSinkDeliverWait caps post-bench rx drain wait (was 2s).
	connectUDPSynthGateSinkDeliverWait = 750 * time.Millisecond
	// connectUDPSynthUploadTailSlackPkts: in-flight at half-close not counted as loss (H2 bulk TLS parity).
	connectUDPSynthUploadTailSlackPkts = 4
	// connectUDPSynthUploadTailSlackPktsPacedSteady: async C2S onward queue (4096) + batch 128 + paced @1000 steady MTU teardown.
	connectUDPSynthUploadTailSlackPktsPacedSteady = 96
	// connectUDPSynthUploadDrainTimeout bounds in-proc synth upload drain (not docker TLS 30s).
	connectUDPSynthUploadDrainTimeout = 2 * time.Second
	// connectUDPEchoDownloadPrimeDepth: in-flight cap for unlimited bg WriteTo + prime depth (pipeline localize shape).
	connectUDPEchoDownloadPrimeDepth = 128
	// connectUDPEchoBoundedPipelineDepth: primary prod-shaped echo gate (3ck ACTIVATED 2026-06-24).
	connectUDPEchoBoundedPipelineDepth = 64
	// connectUDPEchoBoundedPipelineMinMbps: primary H3 echo floor (cold ~497, hot ~380-483).
	connectUDPEchoBoundedPipelineMinMbps = 400.0
	// connectUDPDockerEchoAbsoluteFloorMbps matches run_local.py echo_floor for SOCKS connect-udp profiles.
	connectUDPDockerEchoAbsoluteFloorMbps = 200.0
)

// Legacy docker paced probe band (BENCH_UDP_TARGET_MBIT=8) — localize/regression only, not GATE DoD.
// Compensated pacing (PaceSleepUntil) targets sink goodput ≈ target; floor uses MinPacedGoodputMbit.
const (
	dockerBenchUDPTargetMbit       = 8.0 // docker/masque-perf-lab BENCH_UDP_TARGET_MBIT
	connectUDPLegacyPacedMinMbps = 7.0
	connectUDPLegacyPacedMaxMbps = 8.5
)

// CPU budget gates (ns/byte on fixed 4 MiB bench via testing.Benchmark). Update AGENTS.md after each run.
// Implied CPU-only ceiling ≈ 8000/nsPerB Mbit/s when no FC/scheduling stall.
const (
	masqueCPUBenchBytes = 4 * 1024 * 1024

	connectStreamL0DownloadMaxNsPerB  = 80.0   // loopback TCP WriteTo; measured ~33 ns/B order varies
	connectStreamL1DownloadMaxNsPerB  = 80.0   // prod CONNECT-stream H3 instant WriteTo

	connectUDPL0UploadMaxNsPerB       = 25.0   // loopback UDP; measured ~6.5
	connectUDPL1H3UploadMaxNsPerB     = 40.0   // CONNECT-UDP H3 WriteTo; measured ~11–33 (variance)
	connectUDPL1H3DownloadMaxNsPerB   = 45.0   // CONNECT-UDP H3 ReadFrom+echo feed; calibrate on CI
	connectUDPL1H2UploadMaxNsPerB     = 150.0  // CONNECT-UDP H2 capsule WriteTo; measured ~61
	connectUDPL1H2DownloadMaxNsPerB   = 250.0  // CONNECT-UDP H2 ReadFrom+echo feed; calibrate on CI

	serverRelayTwoGoroutineMaxNsPerB = 150.0 // stream/relay instant bidi; see relay_cpu_bench_test.go
)

// synthCPUMbpsCeiling returns rough CPU-only Mbps ceiling from ns/byte (8 bits/ns formula).
func synthCPUMbpsCeiling(nsPerByte float64) float64 {
	if nsPerByte <= 0 {
		return 0
	}
	return 8000.0 / nsPerByte
}

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

// synthInstantGatePass reports whether Mbps meets instant-link GATE (500 target −3% slack).
func synthInstantGatePass(mbps float64) bool {
	return mbps >= connectUDPSynthInstantMinMbps*(1-connectUDPSynthInstantGateSlackPct)
}

// connectUDPSynthInstantDownloadMinMbps returns fountain S2C synth gate target (Linux DoD path vs desktop regression band).
func connectUDPSynthInstantDownloadMinMbps() float64 {
	switch runtime.GOOS {
	case "windows", "darwin":
		return connectUDPSynthRegressionFloorDownMbpsDesktop
	default:
		return connectUDPSynthInstantMinMbps
	}
}

// synthInstantDownloadGatePass reports whether fountain S2C Mbps meets platform synth gate (−3% slack).
func synthInstantDownloadGatePass(mbps float64) bool {
	return mbps >= connectUDPSynthInstantDownloadMinMbps()*(1-connectUDPSynthInstantGateSlackPct)
}

// connectUDPParallelScalingMinAggMbps returns aggregate floor for N-stream intra-session gate.
func connectUDPParallelScalingMinAggMbps(layer string, streams int, singleMbps float64) float64 {
	if streams < 1 {
		streams = 1
	}
	minAgg := singleMbps * float64(streams) * 0.55
	if minAgg < 250 {
		minAgg = 250
	}
	switch runtime.GOOS {
	case "windows", "darwin":
		switch layer {
		case "h3":
			minAgg = 60.0 * float64(streams)
		case "h2":
			minAgg = singleMbps * float64(streams) * 0.55
			if minAgg > 500 {
				minAgg = 500
			}
			if minAgg < 150*float64(streams) {
				minAgg = 150 * float64(streams)
			}
		}
	default:
		if singleMbps >= connectUDPSynthProdMinMbps*(1-connectUDPSynthInstantGateSlackPct) {
			want := connectUDPSynthProdMinMbps * float64(streams) * 0.7
			if want > connectUDPSynthProdMinMbps {
				want = connectUDPSynthProdMinMbps
			}
			if want > minAgg {
				minAgg = want
			}
		}
		if minAgg > 500 {
			minAgg = 500
		}
	}
	if minAgg > 500 && runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		minAgg = 500
	}
	return minAgg
}

// synthProdGatePass reports whether Mbps meets DoD prod synth (1000 Mbit/s −3% slack).
func synthProdGatePass(mbps float64) bool {
	return mbps >= connectUDPSynthProdMinMbps*(1-connectUDPSynthInstantGateSlackPct)
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

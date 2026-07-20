//go:build masque_inttest_heavy

package inttest

// P6-D1-H2-L1-BISECT: compare H2 download ceiling on minimal L1 pipe vs full native session.

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque"
)

const (
	l1BisectBenchDur          = NativeSynthBenchDur
	l1BisectMinBytes          = 8 * 1024 * 1024
	l1BisectNativeL1MinRatio  = 0.85 // L1 should not lag native session (session adds tax)
	l1BisectNativeL1MaxRatio  = 2.50 // L1 may exceed native (minimal stack vs full session overhead)
	l1BisectH2DownBandFloor   = h2PerfDownFloor
	l1BisectH2DownBandCeiling = h2PerfDownCeiling
	l1BisectL1PipeMaxNsPerB   = 45.0 // arch connectIPL1PipeDownloadMaxNsPerB
)

type l1BisectSample struct {
	Layer string
	Leg   string
	ThroughputSample
}

// RunGATEConnectIPH2L1PipeBisect compares minimal H2 L1 pipe download vs native session download.
func RunGATEConnectIPH2L1PipeBisect(t *testing.T) {
	t.Helper()
	l1 := runL1PipeDownloadLeg(t)
	native := runNativeDownloadLeg(t, "h2")
	logAndAnalyzeL1Bisect(t, l1, native)
}

func runL1PipeDownloadLeg(t *testing.T) l1BisectSample {
	t.Helper()
	stack := openConnectIPH2L1Pipe(t)
	sample := runL1DownloadSample(t, stack, "l1-pipe", l1BisectBenchDur)
	return l1BisectSample{Layer: "l1-pipe", Leg: "download", ThroughputSample: sample}
}

func runNativeDownloadLeg(t *testing.T, layer string) l1BisectSample {
	t.Helper()
	r := runConnectIPThroughputLegs(t, layer, StartNativeConnectIPH2Server, NativeH2ClientOptions)
	return l1BisectSample{Layer: layer + "-native", Leg: "download", ThroughputSample: r.Download}
}

func logAndAnalyzeL1Bisect(t *testing.T, l1, native l1BisectSample) {
	t.Helper()
	t.Logf("BISECT %s", l1)
	t.Logf("BISECT %s", native)

	if l1.Bytes < l1BisectMinBytes || native.Bytes < l1BisectMinBytes {
		t.Fatalf("bisect bytes too small: l1=%d native=%d want>=%d", l1.Bytes, native.Bytes, l1BisectMinBytes)
	}

	ratio := l1.Mbps / native.Mbps
	t.Logf("BISECT L1/native download ratio=%.2f (l1=%.1f native=%.1f Mbit/s)", ratio, l1.Mbps, native.Mbps)

	for _, s := range []ThroughputSample{l1.ThroughputSample, native.ThroughputSample} {
		if s.Mbps < l1BisectH2DownBandFloor || s.Mbps > l1BisectH2DownBandCeiling {
			t.Fatalf("%s %s %.1f outside H2 ceiling band [%.0f, %.0f]",
				s.Layer, s.Leg, s.Mbps, l1BisectH2DownBandFloor, l1BisectH2DownBandCeiling)
		}
	}

	if ratio < l1BisectNativeL1MinRatio {
		t.Fatalf("L1/native ratio %.2f < %.2f — session layer adds unexpected tax (l1=%.1f native=%.1f)",
			ratio, l1BisectNativeL1MinRatio, l1.Mbps, native.Mbps)
	}
	if ratio > l1BisectNativeL1MaxRatio {
		t.Fatalf("L1/native ratio %.2f > %.2f — L1 implausibly faster than session (harness bug? l1=%.1f native=%.1f)",
			ratio, l1BisectNativeL1MaxRatio, l1.Mbps, native.Mbps)
	}

	cpuCeil := masque.SynthCPUMbpsCeiling(l1BisectL1PipeMaxNsPerB)
	if l1.NsPerByte >= l1BisectL1PipeMaxNsPerB {
		t.Logf("BISECT L1 at/beyond L1-pipe CPU anchor ns/B=%.1f (arch max=%.1f => ceil≈%.0f) observed=%.1f",
			l1.NsPerByte, l1BisectL1PipeMaxNsPerB, cpuCeil, l1.Mbps)
	} else {
		t.Logf("BISECT L1 below L1-pipe CPU anchor: ns/B=%.1f arch_max=%.1f ceil≈%.0f observed=%.1f — tax is wire/H2 structural",
			l1.NsPerByte, l1BisectL1PipeMaxNsPerB, cpuCeil, l1.Mbps)
	}

	if ratio >= l1BisectNativeL1MinRatio && ratio <= l1BisectNativeL1MaxRatio {
		t.Logf("BISECT PASS: H2 ~%.0f Mbit/s at L1-pipe (L1/native=%.2f), not coreSession/TUN tax",
			l1.Mbps, ratio)
	}
}

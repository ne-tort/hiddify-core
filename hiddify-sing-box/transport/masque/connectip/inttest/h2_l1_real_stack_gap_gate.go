//go:build masque_inttest_heavy

package inttest

// P6-D1-H2-REAL-STACK-GAP: synth at MSS vs real L1 TCP — localizes tax below/above in-memory ReadPacket.
// Payload size is NOT a prod lever here: TCP already runs at MSS; gate must not treat scaling as fix.

import (
	"testing"
)

const (
	realStackGapBenchDur         = NativeSynthBenchDur
	realStackGapMinBytes         = 4 * 1024 * 1024
	realStackGapSynthIP512       = 540  // matches UDP 512B IP diagnostic leg
	realStackGapSynthIPMSS       = 1500 // Ethernet MSS IP frame (20+20+1460) — TCP bulk profile
	realStackGapSynthRealMin     = 1.00 // synth≈real at MSS after bulk ingress; gate guards regression only
	realStackGapSynthScaleMin    = 1.15
	realStackGapTCPBandFloor     = h2PerfDownFloor
	realStackGapTCPBandCeiling   = h2PerfDownCeiling
	realStackGapByteNsPerBMin    = 3.0
	realStackGapByteNsPerBMax    = 12.0
	realStackGapS2CContextBytes  = 1
)

// RunGATEConnectIPH2RealStackGapAtMSS proves real L1 H2 meets SLO at MSS with synth still faster.
func RunGATEConnectIPH2RealStackGapAtMSS(t *testing.T) {
	t.Helper()
	synth512 := runSyntheticH2ReadPacketSample(t, realStackGapSynthIP512, realStackGapBenchDur)
	synthMSS := runSyntheticH2ReadPacketSample(t, realStackGapSynthIPMSS, realStackGapBenchDur)

	stack := openConnectIPH2L1Pipe(t)
	tcpS2C := runL1DownloadWithS2CStats(t, stack, "l1-tcp", realStackGapBenchDur)

	logAndAnalyzeRealStackGap(t, synth512, synthMSS, tcpS2C)
}

func logAndAnalyzeRealStackGap(t *testing.T, synth512, synthMSS ThroughputSample, tcp connWireS2CResult) {
	t.Helper()
	tcpSample := tcp.Client
	t.Logf("REAL-STACK synth512 %s", synth512)
	t.Logf("REAL-STACK synthMSS %s", synthMSS)
	t.Logf("REAL-STACK tcp %s", tcpSample)

	if tcpSample.Bytes < realStackGapMinBytes {
		t.Fatalf("L1 TCP bytes=%d want>=%d", tcpSample.Bytes, realStackGapMinBytes)
	}
	if tcpSample.Mbps < realStackGapTCPBandFloor || tcpSample.Mbps > realStackGapTCPBandCeiling {
		t.Fatalf("L1 TCP %.1f outside ceiling band [%.0f, %.0f]", tcpSample.Mbps, realStackGapTCPBandFloor, realStackGapTCPBandCeiling)
	}
	if tcpSample.NsPerByte < realStackGapByteNsPerBMin || tcpSample.NsPerByte > realStackGapByteNsPerBMax {
		t.Fatalf("L1 TCP ns/B=%.1f outside byte-tax band [%.0f, %.0f]", tcpSample.NsPerByte, realStackGapByteNsPerBMin, realStackGapByteNsPerBMax)
	}

	synthRealMSS := synthMSS.Mbps / tcpSample.Mbps
	synthScale := synthMSS.Mbps / synth512.Mbps
	byteCeilMbps := 1e9 / tcpSample.NsPerByte * 8 / 1e6

	wallSec := tcpSample.Wall.Seconds()
	serverPPS := 0.0
	avgIPBytes := 0.0
	if tcp.ServerDatagrams > 0 && wallSec > 0 {
		serverPPS = float64(tcp.ServerDatagrams) / wallSec
		serverIP := int64(tcp.ServerDatagramBytes) - int64(tcp.ServerDatagrams)*realStackGapS2CContextBytes
		avgIPBytes = float64(serverIP) / float64(tcp.ServerDatagrams)
	}

	t.Logf("REAL-STACK synthMSS/realTCP=%.2f synthMSS/synth512=%.2f (synthMSS=%.1f realTCP=%.1f)",
		synthRealMSS, synthScale, synthMSS.Mbps, tcpSample.Mbps)
	t.Logf("REAL-STACK byte-tax: ns/B=%.1f implied_ceiling=%.0f Mbit/s (observed=%.1f)",
		tcpSample.NsPerByte, byteCeilMbps, tcpSample.Mbps)
	if serverPPS > 0 {
		t.Logf("REAL-STACK server S2C: datagrams=%d pps=%.0f avg_ip_bytes=%.0f flushes=%d",
			tcp.ServerDatagrams, serverPPS, avgIPBytes, tcp.ServerFlushes)
	}

	if synthRealMSS < realStackGapSynthRealMin {
		t.Fatalf("synthMSS/realTCP %.2f < %.2f — real H2 stack gap missing at MSS (harness/regression)",
			synthRealMSS, realStackGapSynthRealMin)
	}
	if synthScale < realStackGapSynthScaleMin {
		t.Fatalf("synthMSS/synth512 %.2f < %.2f — in-memory pipe should scale (not same fixed wall as real)",
			synthScale, realStackGapSynthScaleMin)
	}

	t.Logf("REAL-STACK PASS: real H2 ~%.0f Mbit/s at MSS (synthMSS/real=%.2f)", tcpSample.Mbps, synthRealMSS)
}

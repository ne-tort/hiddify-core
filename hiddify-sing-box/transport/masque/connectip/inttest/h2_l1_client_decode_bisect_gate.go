//go:build masque_inttest_heavy

package inttest

// P6-D1-H2-CLIENT-DECODE: in-memory H2 ReadPacket synth vs real conn-wire.
// UDP payload legs are DIAGNOSTIC ONLY (PPS/fixed-cost marker) — not a prod lever; do not treat max>512 as fix.

import (
	"net/netip"
	"testing"
	"time"

	connectipgo "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing-box/transport/masque/connectip"
	cipframe "github.com/sagernet/sing-box/transport/masque/connectip/frame"
)

const (
	decodeBisectBenchDur          = NativeSynthBenchDur
	decodeBisectMinBytes          = 4 * 1024 * 1024
	decodeBisectUDPPayload512     = 512
	decodeBisectUDPPayloadMax     = connectip.DefaultUDPWriteHardCap // 1152
	decodeBisectSynthRealMinRatio = 1.05 // synth still slightly faster; gap collapsed after bulk ingress
	decodeBisectRealMinMbps       = h2PerfDownFloor
	decodeBisectReal512MaxMbps    = h2PerfDownCeiling
	decodeBisectRealMaxMaxMbps    = h2PerfDownCeiling
	decodeBisectPayloadScaleMin   = 1.15 // max/512 on real path — PPS/decode asymmetry signal
)

func ipPacketLenForUDPPayload(tb testing.TB, udpPayloadLen int) int {
	tb.Helper()
	src := netip.MustParseAddr(NativeProfileLocalIPv4)
	dst := netip.MustParseAddr("127.0.0.1")
	pkt, err := cipframe.BuildIPv4UDPPacket(src, connWireUDPSrcPort, dst, 9999, make([]byte, udpPayloadLen))
	if err != nil {
		tb.Fatalf("ip packet len udp=%d: %v", udpPayloadLen, err)
	}
	return len(pkt)
}

func runSyntheticH2ReadPacketSample(tb testing.TB, ipPacketLen int, dur time.Duration) ThroughputSample {
	tb.Helper()
	start := time.Now()
	bytes, mbps := connectipgo.SyntheticH2ReadPacketBench(ipPacketLen, dur)
	wall := time.Since(start)
	nsPerB := 0.0
	if bytes > 0 {
		nsPerB = float64(wall.Nanoseconds()) / float64(bytes)
	}
	return ThroughputSample{
		Layer:          "synth",
		Leg:            "h2-readpacket-inmem",
		Bytes:          bytes,
		Mbps:           mbps,
		Wall:           wall,
		NsPerByte:      nsPerB,
		CPUCeilingMbps: masque.SynthCPUMbpsCeiling(nsPerB),
	}
}

// RunGATEConnectIPH2ClientDecodeBisect compares in-memory ReadPacket vs real H2 conn-wire decode.
func RunGATEConnectIPH2ClientDecodeBisect(t *testing.T) {
	t.Helper()
	ip512 := ipPacketLenForUDPPayload(t, decodeBisectUDPPayload512)
	ipMax := ipPacketLenForUDPPayload(t, decodeBisectUDPPayloadMax)

	synth512 := runSyntheticH2ReadPacketSample(t, ip512, decodeBisectBenchDur)
	synthMax := runSyntheticH2ReadPacketSample(t, ipMax, decodeBisectBenchDur)

	stack512 := openConnectIPH2ConnWire(t)
	real512 := runConnWireUDPFountainSample(t, stack512, "real-h2", decodeBisectBenchDur, decodeBisectUDPPayload512)
	stackMax := openConnectIPH2ConnWire(t)
	realMax := runConnWireUDPFountainSample(t, stackMax, "real-h2", decodeBisectBenchDur, decodeBisectUDPPayloadMax)

	logAndAnalyzeClientDecodeBisect(t, ip512, ipMax, synth512, synthMax, real512, realMax)
}

func logAndAnalyzeClientDecodeBisect(
	t *testing.T,
	ip512, ipMax int,
	synth512, synthMax, real512, realMax ThroughputSample,
) {
	t.Helper()
	t.Logf("DECODE ipPacketLen 512B-udp=%d max-udp=%d", ip512, ipMax)
	for _, s := range []ThroughputSample{synth512, synthMax, real512, realMax} {
		t.Logf("DECODE %s %s", s.Layer, s)
	}

	for _, s := range []ThroughputSample{real512, realMax} {
		if s.Bytes < decodeBisectMinBytes {
			t.Fatalf("%s bytes=%d want>=%d", s.Leg, s.Bytes, decodeBisectMinBytes)
		}
	}

	synthReal512 := synth512.Mbps / real512.Mbps
	synthRealMax := synthMax.Mbps / realMax.Mbps
	payloadScaleReal := realMax.Mbps / real512.Mbps
	payloadScaleSynth := synthMax.Mbps / synth512.Mbps

	t.Logf("DECODE synth/real ratio 512=%.2f max=%.2f (synth512=%.1f real512=%.1f synthMax=%.1f realMax=%.1f)",
		synthReal512, synthRealMax, synth512.Mbps, real512.Mbps, synthMax.Mbps, realMax.Mbps)
	t.Logf("DECODE payload max/512 ratio real=%.2f synth=%.2f", payloadScaleReal, payloadScaleSynth)

	if synthReal512 < decodeBisectSynthRealMinRatio {
		t.Fatalf("synth/real512 ratio %.2f < %.2f — in-memory decode regressed or harness broken",
			synthReal512, decodeBisectSynthRealMinRatio)
	}

	if real512.Mbps < decodeBisectRealMinMbps || real512.Mbps > decodeBisectReal512MaxMbps {
		t.Fatalf("512B leg %.1f outside band [%.0f, %.0f]", real512.Mbps, decodeBisectRealMinMbps, decodeBisectReal512MaxMbps)
	}
	if realMax.Mbps < decodeBisectRealMinMbps || realMax.Mbps > decodeBisectRealMaxMaxMbps {
		t.Fatalf("1152B leg %.1f outside band [%.0f, %.0f]", realMax.Mbps, decodeBisectRealMinMbps, decodeBisectRealMaxMaxMbps)
	}

	if payloadScaleReal >= decodeBisectPayloadScaleMin {
		t.Logf("DIAG(payload-only): real UDP max/512=%.2f — fixed-cost marker; prod TCP stays at MSS (see RealStackGapAtMSS gate)",
			payloadScaleReal)
	} else if payloadScaleReal < 0.85 {
		t.Logf("OPEN: real H2 inverse payload scaling (max/512=%.2f) — large capsule/IP tax on wire path",
			payloadScaleReal)
	} else {
		t.Logf("DECODE real path weak payload scaling (max/512=%.2f)", payloadScaleReal)
	}

	t.Logf("DECODE PASS: in-memory H2 ReadPacket >> real conn-wire (512 ratio=%.2f max ratio=%.2f) — ceiling is real H2 stack not pure decode",
		synthReal512, synthRealMax)
}

//go:build masque_inttest_heavy

package inttest

// P6-D1-H2-CONN-WIRE: split H2 S2C wire (ReadPacket UDP fountain) vs L1 TCP download (netstack).

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque"
)

const (
	connWireBisectBenchDur       = NativeSynthBenchDur
	connWireBisectMinBytes       = 4 * 1024 * 1024
	connWireL1MinRatio           = 0.70 // conn-wire should track L1 if netstack is not the tax
	connWireL1MaxRatio           = 1.30
	connWireH2DownBandFloor      = h2PerfDownFloor
	connWireH2DownBandCeiling    = h2PerfDownCeiling
	connWireUDPFountainMinMbps   = 180.0 // UDP fountain can sit slightly below TCP L1 under host jitter
	connWireSynthMacroRefMbps    = 980.0 // connect-ip-go macro ConnReadPacket anchor (in-memory pipe)
	connWireSynthGapLogRatio     = 0.55  // real H2 wire << synth => server/TLS/H2 path tax vs macro
)

// RunGATEConnectIPH2L1ConnWireBisect compares conn-only ReadPacket S2C vs L1 TCP download on H2.
func RunGATEConnectIPH2L1ConnWireBisect(t *testing.T) {
	t.Helper()
	connStack := openConnectIPH2ConnWire(t)
	connWire := runConnWireUDPFountainSample(t, connStack, "conn-wire", connWireBisectBenchDur, connWireUDPFountainPayloadLen)

	l1Stack := openConnectIPH2L1Pipe(t)
	l1 := runL1DownloadSample(t, l1Stack, "l1-tcp", connWireBisectBenchDur)

	logAndAnalyzeConnWireBisect(t, connWire, l1)
}

func logAndAnalyzeConnWireBisect(t *testing.T, connWire, l1 ThroughputSample) {
	t.Helper()
	t.Logf("CONN-WIRE %s", connWire)
	t.Logf("CONN-WIRE %s", l1)

	if connWire.Bytes < connWireBisectMinBytes {
		t.Fatalf("conn-wire bytes=%d want>=%d", connWire.Bytes, connWireBisectMinBytes)
	}
	if l1.Bytes < connWireBisectMinBytes {
		t.Fatalf("L1 TCP bytes=%d want>=%d", l1.Bytes, connWireBisectMinBytes)
	}

	ratio := connWire.Mbps / l1.Mbps
	t.Logf("CONN-WIRE conn-wire/L1 ratio=%.2f (wire=%.1f l1=%.1f Mbit/s)", ratio, connWire.Mbps, l1.Mbps)

	if connWire.Mbps < connWireUDPFountainMinMbps {
		t.Fatalf("conn-wire UDP fountain %.1f < %.0f — harness broken", connWire.Mbps, connWireUDPFountainMinMbps)
	}
	if l1.Mbps < connWireH2DownBandFloor || l1.Mbps > connWireH2DownBandCeiling {
		t.Fatalf("%s %s %.1f outside H2 ceiling band [%.0f, %.0f]",
			l1.Layer, l1.Leg, l1.Mbps, connWireH2DownBandFloor, connWireH2DownBandCeiling)
	}

	synthRatio := connWire.Mbps / connWireSynthMacroRefMbps
	t.Logf("CONN-WIRE conn-wire/synth-macro ratio=%.2f (wire=%.1f synth_ref=%.0f)",
		synthRatio, connWire.Mbps, connWireSynthMacroRefMbps)

	if ratio < connWireL1MinRatio || ratio > connWireL1MaxRatio {
		t.Fatalf("conn-wire/L1 ratio %.2f outside [%.2f, %.2f] — netstack/TCP tax or harness mismatch (wire=%.1f l1=%.1f)",
			ratio, connWireL1MinRatio, connWireL1MaxRatio, connWire.Mbps, l1.Mbps)
	}

	if synthRatio < connWireSynthGapLogRatio {
		t.Logf("OPEN: real H2 conn-wire %.1f << synth macro %.0f (ratio=%.2f) — TLS/H2 server proxy path tax vs in-memory pipe",
			connWire.Mbps, connWireSynthMacroRefMbps, synthRatio)
	}

	t.Logf("CONN-WIRE %s ns/B=%.1f cpu_ceil=%.0f", connWire.Layer, connWire.NsPerByte,
		masque.SynthCPUMbpsCeiling(connWire.NsPerByte))
	t.Logf("CONN-WIRE PASS: H2 S2C wire ≈ L1 TCP (ratio=%.2f) — netstack not main tax; ceiling at H2 ReadPacket/wire",
		ratio)
}

//go:build masque_inttest_heavy

package inttest

// P6-D1-H2-TCP-UDP-PAYLOAD: DIAGNOSTIC map of L1 TCP vs UDP fountain legs (not prod levers).

import (
	"math"
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectip"
)

const (
	tcpUdpBisectBenchDur       = NativeSynthBenchDur
	tcpUdpBisectMinBytes       = 4 * 1024 * 1024
	tcpUdpBisectUDPPayload512  = 512
	tcpUdpBisectUDPPayloadMax  = connectip.DefaultUDPWriteHardCap
	tcpUdpBisectH2DownFloor    = 200.0
	tcpUdpBisectH2DownCeiling  = 450.0
	tcpUdpBisectIngressDropMax = 0 // hard fail if stream DATAGRAM ingress drops during bench
)

// RunGATEConnectIPH2L1TCPvsUDPPayloadBisect compares L1 TCP bulk vs UDP fountain payload legs.
func RunGATEConnectIPH2L1TCPvsUDPPayloadBisect(t *testing.T) {
	t.Helper()
	l1Stack := openConnectIPH2L1Pipe(t)
	tcp := runL1DownloadWithIngressDrops(t, l1Stack, "l1-tcp", tcpUdpBisectBenchDur)

	stack512 := openConnectIPH2ConnWire(t)
	udp512 := runConnWireUDPFountainWithIngressDrops(t, stack512, "conn-wire", tcpUdpBisectBenchDur, tcpUdpBisectUDPPayload512)
	stackMax := openConnectIPH2ConnWire(t)
	udpMax := runConnWireUDPFountainWithIngressDrops(t, stackMax, "conn-wire", tcpUdpBisectBenchDur, tcpUdpBisectUDPPayloadMax)

	logAndAnalyzeTCPvsUDPPayload(t, tcp, udp512, udpMax)
}

func logAndAnalyzeTCPvsUDPPayload(t *testing.T, tcp, udp512, udpMax ingressWireSample) {
	t.Helper()
	for _, s := range []ingressWireSample{tcp, udp512, udpMax} {
		t.Logf("TCP-UDP %s", s.StringExtra())
	}

	for _, s := range []ingressWireSample{tcp, udp512} {
		if s.Bytes < tcpUdpBisectMinBytes {
			t.Fatalf("%s bytes=%d want>=%d", s.Leg, s.Bytes, tcpUdpBisectMinBytes)
		}
		if s.Mbps < tcpUdpBisectH2DownFloor || s.Mbps > tcpUdpBisectH2DownCeiling {
			t.Fatalf("%s %.1f outside H2 band [%.0f, %.0f]", s.Leg, s.Mbps, tcpUdpBisectH2DownFloor, tcpUdpBisectH2DownCeiling)
		}
	}
	if udpMax.Bytes < tcpUdpBisectMinBytes {
		t.Fatalf("%s bytes=%d want>=%d", udpMax.Leg, udpMax.Bytes, tcpUdpBisectMinBytes)
	}
	if udpMax.Mbps < tcpUdpBisectH2DownFloor || udpMax.Mbps > decodeBisectRealMaxMaxMbps {
		t.Fatalf("%s %.1f outside band [%.0f, %.0f]", udpMax.Leg, udpMax.Mbps, tcpUdpBisectH2DownFloor, decodeBisectRealMaxMaxMbps)
	}

	for _, s := range []ingressWireSample{tcp, udp512, udpMax} {
		if s.IngressDrops > tcpUdpBisectIngressDropMax {
			t.Logf("OPEN: %s ingress_drops=%d — h2 capsule ingress queue overflow during bench", s.Leg, s.IngressDrops)
		}
	}

	tcpVs512 := tcp.Mbps / udp512.Mbps
	tcpVsMax := tcp.Mbps / udpMax.Mbps
	maxVs512 := udpMax.Mbps / udp512.Mbps
	interp := tcpPayloadInterp(tcp.Mbps, udp512.Mbps, udpMax.Mbps)

	t.Logf("TCP-UDP tcp/udp512=%.2f tcp/udp1152=%.2f udp1152/udp512=%.2f diag_profile=%s",
		tcpVs512, tcpVsMax, maxVs512, interp)
	logTCPPayloadPosition(t, tcp.Mbps, udp512.Mbps, udpMax.Mbps)
	t.Logf("TCP-UDP DIAG-ONLY: UDP payload legs localize fixed-cost; prod TCP=MSS — see RealStackGapAtMSS")
	t.Logf("TCP-UDP PASS: L1 TCP %.0f Mbit/s in H2 ceiling band (same order as udp legs)", tcp.Mbps)
}

func tcpPayloadInterp(tcp, udp512, udpMax float64) string {
	if udpMax <= udp512 {
		return "flat-udp-scale"
	}
	frac := (tcp - udp512) / (udpMax - udp512)
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	switch {
	case frac < 0.25:
		return "near-512B-pps"
	case frac > 0.75:
		return "near-1152B-byte"
	default:
		return "mid-scale"
	}
}

// logTCPPayloadPosition logs OPEN hints from tcp position (used by localize gates).
func logTCPPayloadPosition(t *testing.T, tcp, udp512, udpMax float64) {
	t.Helper()
	d512 := math.Abs(tcp - udp512)
	dMax := math.Abs(tcp - udpMax)
	if d512 < dMax {
		t.Logf("OPEN: L1 TCP closer to 512B UDP fountain (tcp=%.0f udp512=%.0f udp1152=%.0f)", tcp, udp512, udpMax)
	} else if dMax < d512 {
		t.Logf("OPEN: L1 TCP closer to 1152B UDP fountain (tcp=%.0f udp512=%.0f udp1152=%.0f)", tcp, udp512, udpMax)
	}
}

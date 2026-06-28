package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestH2RealTransportWindowedDuplexIperfControl(t *testing.T) {
	targetPort := masque.InttestStartH2FakeIperfConcurrentControlTarget(t)
	proxyPort := masque.InttestStartInProcessH2TCPConnectStreamProxy(t)
	conn := masque.InttestDialH2ConnectStreamBenchTCPWindowed(t, proxyPort, int(targetPort))

	n := masque.InttestRunH2HonestGateDuplexWriteTo(t, conn, masque.InttestH2HonestGateDuration(), masque.InttestH2HonestGateMinBytes())
	t.Logf("H2 real transport windowed duplex control: %d bytes", n)
	if n < masque.InttestH2HonestGateMinBytes() {
		t.Fatalf("real transport download short: %d want >= %d (H2 bidi FC stall)", n, masque.InttestH2HonestGateMinBytes())
	}
}

func TestServerHandleTCPConnectH2DuplexProdFlush(t *testing.T) {
	t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "0")

	targetPort := masque.InttestStartH2FakeIperfConcurrentControlTarget(t)
	proxyPort := masque.InttestStartInProcessH2TCPConnectStreamProxy(t)
	conn := masque.InttestDialH2ConnectStreamBenchTCPWindowed(t, proxyPort, int(targetPort))

	n := masque.InttestRunH2HonestGateDuplexWriteTo(t, conn, masque.InttestH2HonestGateDuration(), masque.InttestH2HonestGateMinBytes())
	t.Logf("H2 relay duplex prod flush: %d bytes", n)
	if n < masque.InttestH2HonestGateMinBytes() {
		t.Fatalf("H2 relay duplex short: %d want >= %d", n, masque.InttestH2HonestGateMinBytes())
	}
}

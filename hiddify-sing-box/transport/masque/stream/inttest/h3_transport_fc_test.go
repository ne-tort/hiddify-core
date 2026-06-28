package inttest_test

import (
	"testing"
	"time"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestH3RealTransportWindowedDuplexIperfControl(t *testing.T) {
	targetPort := masque.InttestStartH2FakeIperfConcurrentControlTarget(t)
	conn := masque.InttestDialH3ConnectStreamBench(t, int(targetPort))
	if err := conn.SetDeadline(time.Now().Add(masque.InttestH3HonestGateDuration() + 8*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	n := masque.InttestRunH3HonestGateDuplexWriteTo(t, conn, masque.InttestH3HonestGateDuration(), masque.InttestH3HonestGateMinBytes())
	t.Logf("H3 real transport duplex control: %d bytes", n)
	if n < masque.InttestH3HonestGateMinBytes() {
		t.Fatalf("real H3 transport download short: %d want >= %d (H3 bidi FC stall)", n, masque.InttestH3HonestGateMinBytes())
	}
}

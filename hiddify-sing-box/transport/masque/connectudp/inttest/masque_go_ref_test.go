//go:build masque_ref

package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestBenchConnectUDPH3FountainMasqueGoRefMatrix(t *testing.T) {
	masque.InttestBenchConnectUDPH3FountainMasqueGoRefMatrix(t)
}

func TestBenchConnectUDPH3FountainMasqueGoRef(t *testing.T) {
	masque.InttestBenchConnectUDPH3FountainMasqueGoRef(t)
}

func TestBenchConnectUDPH3EchoRelayVsRef(t *testing.T) {
	masque.InttestBenchConnectUDPH3EchoRelayVsRef(t)
}

func TestLocalizeConnectUDPH3FountainRelayVsRef(t *testing.T) {
	masque.InttestLocalizeConnectUDPH3FountainRelayVsRef(t)
}

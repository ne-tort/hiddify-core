package inttest

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque"
)

func TestGATEConnectIPPacketPlaneC2SFlood(t *testing.T) {
	masque.InttestGATEConnectIPPacketPlaneC2SFlood(t)
}

func TestGATEConnectIPPacketPlaneRoundTrip(t *testing.T) {
	masque.InttestGATEConnectIPPacketPlaneRoundTrip(t)
}

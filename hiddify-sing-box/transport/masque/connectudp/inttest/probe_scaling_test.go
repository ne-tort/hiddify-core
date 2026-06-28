package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestProbeConnectUDPScalingCeiling(t *testing.T) {
	masque.InttestProbeConnectUDPScalingCeiling(t)
}

func TestProbeConnectUDPIntraVsInterScaling(t *testing.T) {
	masque.InttestProbeConnectUDPIntraVsInterScaling(t)
}

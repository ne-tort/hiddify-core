package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestProbeConnectUDPScalingCeiling(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestProbeConnectUDPScalingCeiling(t)
}

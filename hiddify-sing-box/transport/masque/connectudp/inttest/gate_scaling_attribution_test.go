package inttest_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque"
)

func TestLocalizeConnectUDPH3ParallelScalingAttribution(t *testing.T) {
	masque.SkipUnlessMasqueBenchLong(t)
	masque.InttestLocalizeConnectUDPH3ParallelScalingAttribution(t)
}

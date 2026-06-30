package masque

import "testing"

func InttestProbeConnectUDPScalingCeiling(t *testing.T) {
	if testing.Short() {
		t.Skip("scaling ceiling probe")
	}
	for _, layer := range []string{"h2", "h3"} {
		layer := layer
		t.Run(layer, func(t *testing.T) {
			probeConnectUDPScalingCeiling(t, layer, []int{1, 2, 4})
		})
	}
}

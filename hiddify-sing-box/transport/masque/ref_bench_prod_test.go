package masque

import (
	"time"

	"github.com/sagernet/sing-box/transport/masque/h3"
)

// benchProdTunnelConnMockDuplexMinMbps measures prod TunnelConn duplex on infinite mock stream
// using the same measureSegmentDuplexMbps harness as REF paired tests.
func benchProdTunnelConnMockDuplexMinMbps(duration time.Duration) float64 {
	c := h3.NewTunnelConn(h3.TunnelConnParams{
		H3Stream:        h3.NewRefBenchInfiniteStream(),
		RouteBidiDuplex: true,
	})
	_, _, minLeg, err := measureSegmentDuplexMbps(c, duration)
	if err != nil {
		return 0
	}
	return minLeg
}

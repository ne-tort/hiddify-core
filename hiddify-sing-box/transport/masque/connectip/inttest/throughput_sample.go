package inttest

import (
	"fmt"
	"net"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
)

// ThroughputSample captures one timed bulk leg with CPU-localize metrics.
type ThroughputSample struct {
	Layer          string
	Leg            string
	Bytes          int64
	Mbps           float64
	Wall           time.Duration
	NsPerByte      float64
	CPUCeilingMbps float64
}

func (s ThroughputSample) String() string {
	return fmt.Sprintf("%s %s: %.1f Mbit/s (%d B wall=%s ns/B=%.1f cpu_ceil=%.0f)",
		s.Layer, s.Leg, s.Mbps, s.Bytes, s.Wall.Round(time.Millisecond), s.NsPerByte, s.CPUCeilingMbps)
}

func measureDownloadSample(layer, leg string, conn net.Conn, dur time.Duration) ThroughputSample {
	start := time.Now()
	bytes, mbps, _ := masque.MeasureNativeDownloadReadMbps(conn, dur)
	wall := time.Since(start)
	nsPerB := 0.0
	if bytes > 0 {
		nsPerB = float64(wall.Nanoseconds()) / float64(bytes)
	}
	return ThroughputSample{
		Layer:          layer,
		Leg:            leg,
		Bytes:          bytes,
		Mbps:           mbps,
		Wall:           wall,
		NsPerByte:      nsPerB,
		CPUCeilingMbps: masque.SynthCPUMbpsCeiling(nsPerB),
	}
}

func measureUploadSample(layer, leg string, conn net.Conn, dur time.Duration) ThroughputSample {
	start := time.Now()
	bytes, mbps, _ := masque.MeasureNativeUploadMbps(conn, dur)
	wall := time.Since(start)
	nsPerB := 0.0
	if bytes > 0 {
		nsPerB = float64(wall.Nanoseconds()) / float64(bytes)
	}
	return ThroughputSample{
		Layer:          layer,
		Leg:            leg,
		Bytes:          bytes,
		Mbps:           mbps,
		Wall:           wall,
		NsPerByte:      nsPerB,
		CPUCeilingMbps: masque.SynthCPUMbpsCeiling(nsPerB),
	}
}

package masque

// usque-shaped CONNECT-IP benchmarks: L0 channel pump, L2 netstack over packet plane.

import (
	"sync/atomic"
	"testing"
	"time"
)

func benchRefUsquePumpMbps(duration time.Duration) float64 {
	dev := newUsqueShapeDevice()
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i)
	}

	go func() {
		buf := make([]byte, 1600)
		for {
			n, err := dev.ReadPacket(buf)
			if err != nil || n == 0 {
				continue
			}
			_ = dev.WritePacket(buf[:n])
		}
	}()

	go func() {
		pkt := make([]byte, len(payload))
		copy(pkt, payload)
		for i := 0; i < 1<<22; i++ {
			dev.in <- pkt
		}
	}()

	var total atomic.Int64
	stop := time.Now().Add(duration)
	go func() {
		for time.Now().Before(stop) {
			select {
			case pkt := <-dev.out:
				total.Add(int64(len(pkt)))
			default:
			}
		}
	}()
	time.Sleep(duration)
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return float64(total.Load()*8) / secs / 1e6
}

func benchRefUsqueNetstackUploadMbps(t *testing.T, duration time.Duration) float64 {
	t.Helper()
	r := benchConnectIPUploadLayer(t, "L2", instantPacketLink{}, duration)
	if r.err != nil {
		t.Fatalf("usque L2 netstack upload: %v", r.err)
	}
	return r.mbps
}

func benchRefUsqueNetstackDownloadMbps(t *testing.T, duration time.Duration) float64 {
	t.Helper()
	r := benchConnectIPDownloadLayer(t, "L2", instantPacketLink{}, duration)
	if r.err != nil {
		t.Fatalf("usque L2 netstack download: %v", r.err)
	}
	return r.mbps
}

package connectip

import (
	"testing"
	"time"
)

func TestSyntheticH2ReadPacketBenchSmoke(t *testing.T) {
	const ipLen = 540
	bytes, mbps := SyntheticH2ReadPacketBench(ipLen, 200*time.Millisecond)
	if bytes <= 0 {
		t.Fatalf("bytes=%d want >0", bytes)
	}
	if mbps < 50 {
		t.Fatalf("mbps=%.1f too low for in-memory pipe", mbps)
	}
	t.Logf("SyntheticH2ReadPacketBench ipLen=%d: %.1f Mbit/s (%d B)", ipLen, mbps, bytes)
}

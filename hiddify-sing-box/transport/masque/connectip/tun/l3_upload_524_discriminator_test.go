//go:build !upload_gate

package tun

import (
	"testing"
	"time"
)

// TestGATEConnectIPUploadBoundDiscriminator (GATE-UP-6) unpaced fast path → UploadBoundUnpaced (all platforms).
func TestGATEConnectIPUploadBoundDiscriminator(t *testing.T) {
	seg := makeUpload524BulkSeg(t)

	unpaced := runHostKernelPumpMeter(t, hostEgressInfinite(seg), &mockL3Writer{}, 150*time.Millisecond, upload524PumpHarnessOpts{})
	logUploadBoundMetrics(t, "unpaced", unpaced)
	if unpaced.Bound != UploadBoundUnpaced {
		t.Fatalf("unpaced bound=%s want %s mbps=%.1f", unpaced.Bound, UploadBoundUnpaced, unpaced.Mbps)
	}
	if unpaced.Mbps <= Upload524MbpsBandHi {
		t.Fatalf("unpaced mbps=%.1f want > %.0f", unpaced.Mbps, Upload524MbpsBandHi)
	}
}

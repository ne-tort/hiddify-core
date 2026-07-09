package quic

import (
	"testing"
	"time"
)

func TestMasqueDownloadDeliveryWakeBatchProd(t *testing.T) {
	t.Parallel()
	if got := MasqueDownloadDeliveryWakeBatch(0, 0); got != masqueDownloadWakeBDPBytes {
		t.Fatalf("zero RTT=%d want %d", got, masqueDownloadWakeBDPBytes)
	}
	const legacy = 256 * 1024
	if got := MasqueDownloadDeliveryWakeBatch(0, 0); got == legacy {
		t.Fatalf("zero RTT batch must not equal legacy http3 default %d", legacy)
	}
	at100 := MasqueDownloadDeliveryWakeBatch(100*time.Millisecond, 0)
	if at100 <= masqueDownloadWakeBDPBytes || at100 > masqueDownloadWakeMaxBytes {
		t.Fatalf("100ms batch=%d want (%d,%d]", at100, masqueDownloadWakeBDPBytes, masqueDownloadWakeMaxBytes)
	}
}

func TestMasqueDownloadDeliveryWakeBatchBDPClamp(t *testing.T) {
	t.Parallel()
	batch := MasqueDownloadDeliveryWakeBatch(35*time.Millisecond, 80*1024)
	if batch > 40*1024 {
		t.Fatalf("clamped batch=%d want <= %d", batch, 40*1024)
	}
	if batch < masqueDownloadWakeMinBytes {
		t.Fatalf("clamped batch=%d below min %d", batch, masqueDownloadWakeMinBytes)
	}
}

func TestMasqueConnSmoothedRTTTestHook(t *testing.T) {
	t.Parallel()
	SetTestMasqueConnSmoothedRTT(42 * time.Millisecond)
	defer ClearTestMasqueConnSmoothedRTT()
	if got := MasqueConnSmoothedRTT(nil); got != 42*time.Millisecond {
		t.Fatalf("hook RTT=%s want 42ms", got)
	}
}

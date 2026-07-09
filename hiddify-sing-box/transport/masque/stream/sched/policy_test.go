package sched

import (
	"testing"
	"time"
)

func TestDownloadDeliveryWakeBatchProd(t *testing.T) {
	t.Parallel()
	if got := DownloadDeliveryWakeBatch(0); got != DownloadDeliveryWakeBDPBytes {
		t.Fatalf("zero RTT=%d want %d", got, DownloadDeliveryWakeBDPBytes)
	}
	at100 := DownloadDeliveryWakeBatch(100 * time.Millisecond)
	if at100 <= DownloadDeliveryWakeBDPBytes || at100 > DownloadDeliveryWakeMaxBytes {
		t.Fatalf("100ms batch=%d want (%d,%d]", at100, DownloadDeliveryWakeBDPBytes, DownloadDeliveryWakeMaxBytes)
	}
}

func TestTheoreticalDownloadCeilingMbps(t *testing.T) {
	t.Parallel()
	ceil := TheoreticalDownloadCeilingMbps(1024*1024, 100*time.Millisecond)
	if ceil < 78 || ceil > 86 {
		t.Fatalf("theoretical@100ms 1MiB=%.1f want ~80", ceil)
	}
}

func TestGATERelayDuplexArmUploadBytesWANHTTPS(t *testing.T) {
	t.Parallel()
	const want = 256 * 1024
	if RelayDuplexArmUploadBytes != want {
		t.Fatalf("RelayDuplexArmUploadBytes=%d want %d (TLS ACKs during download must not arm duplex)", RelayDuplexArmUploadBytes, want)
	}
}

package http2

import (
	"os"
	"strings"
	"testing"
)

func TestGATEMasqueH2ResponseReadUnlocksWmuBeforeWake(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("transport.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	idx := strings.Index(src, "func (b transportResponseBody) Read")
	if idx < 0 {
		t.Fatal("transportResponseBody.Read not found")
	}
	chunk := src[idx:]
	if end := strings.Index(chunk, "\nfunc "); end > 0 {
		chunk = chunk[:end]
	}
	if strings.Contains(chunk, "defer cc.wmu.Unlock()") {
		t.Fatal("H2-W1: transportResponseBody.Read must not defer wmu.Unlock across masqueWake")
	}
	unlock := strings.Index(chunk, "cc.wmu.Unlock()")
	wake := strings.Index(chunk, "masqueWakeRequestBodyWrite")
	if unlock < 0 || wake < 0 || unlock > wake {
		t.Fatalf("H2-W1: Unlock must appear before masqueWakeRequestBodyWrite (unlock=%d wake=%d)", unlock, wake)
	}
}

func TestMasqueH2StatsSnapshotRoundTrip(t *testing.T) {
	t.Parallel()
	ResetMasqueH2StatsForTest()
	if got := SnapshotMasqueH2Stats(); got.DownloadBodyBytes != 0 || got.TransportResets != 0 {
		t.Fatalf("expected zero stats after reset, got %+v", got)
	}
	NoteMasqueH2TransportReset()
	got := SnapshotMasqueH2Stats()
	if got.TransportResets != 1 {
		t.Fatalf("TransportResets=%d want 1", got.TransportResets)
	}
}

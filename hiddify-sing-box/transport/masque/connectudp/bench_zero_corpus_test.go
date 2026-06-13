package connectudp

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestZeroCorpusSHA256Empty(t *testing.T) {
	t.Parallel()
	want := hex.EncodeToString(sha256.New().Sum(nil))
	if got := ZeroCorpusSHA256(0); got != want {
		t.Fatalf("ZeroCorpusSHA256(0) = %q want %q", got, want)
	}
	if got := ZeroCorpusSHA256(-1); got != want {
		t.Fatalf("ZeroCorpusSHA256(-1) = %q want %q", got, want)
	}
}

func TestZeroCorpusSHA256LargeChunkBoundary(t *testing.T) {
	t.Parallel()
	const chunk = 1 << 20
	// Span two 1 MiB chunks to exercise loop boundary.
	got := ZeroCorpusSHA256(chunk + 1)
	if len(got) != 64 {
		t.Fatalf("hash len=%d want 64 hex chars", len(got))
	}
	small := ZeroCorpusSHA256(500)
	large := ZeroCorpusSHA256(50000)
	if small == large {
		t.Fatal("distinct byte counts must produce distinct hashes")
	}
}

func TestUDPProbeFillSHA256DefaultPayload(t *testing.T) {
	t.Parallel()
	const rxPkts = 100
	fillBytes := UDPProbeFillBytes(rxPkts, DefaultBenchUDPPayloadLen)
	if fillBytes != (DefaultBenchUDPPayloadLen-UDPProbeHeaderLen)*rxPkts {
		t.Fatalf("fillBytes=%d want %d", fillBytes, (DefaultBenchUDPPayloadLen-UDPProbeHeaderLen)*rxPkts)
	}
	got := UDPProbeFillSHA256(rxPkts, DefaultBenchUDPPayloadLen)
	want := ZeroCorpusSHA256(fillBytes)
	if got != want {
		t.Fatalf("UDPProbeFillSHA256 = %q want %q", got, want)
	}
}

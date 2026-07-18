package h2

import (
	"bytes"
	"testing"
)

func TestDatagramCapsuleWireLenMatchesEncode(t *testing.T) {
	t.Parallel()
	for _, payload := range [][]byte{nil, {}, {1}, make([]byte, 512), make([]byte, MaxUDPPayloadPerDatagramCapsule())} {
		var buf bytes.Buffer
		if err := AppendDatagramCapsuleWire(&buf, payload); err != nil {
			t.Fatalf("payload len=%d: %v", len(payload), err)
		}
		if got, want := buf.Len(), DatagramCapsuleWireLen(payload); got != want {
			t.Fatalf("payload len=%d: wire len got %d want %d", len(payload), got, want)
		}
	}
}

func TestUDPPayloadWireLenMatchesSingleCapsule(t *testing.T) {
	t.Parallel()
	payload := make([]byte, 512)
	var buf bytes.Buffer
	if err := AppendDatagramCapsuleWire(&buf, payload); err != nil {
		t.Fatal(err)
	}
	if got, want := UDPPayloadWireLen(payload), buf.Len(); got != want {
		t.Fatalf("wire len got %d want %d", got, want)
	}
	// Oversize is still one capsule wire-len estimate (call sites reject before encode).
	big := make([]byte, MaxUDPPayloadPerDatagramCapsule()+17)
	if UDPPayloadWireLen(big) != DatagramCapsuleWireLen(big) {
		t.Fatal("UDPPayloadWireLen must equal DatagramCapsuleWireLen (no split)")
	}
}

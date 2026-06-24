package relay

import (
	"bytes"
	"io"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

func encodeCapsulePayload(ct http3.CapsuleType, payload []byte) []byte {
	var b []byte
	b = quicvarint.Append(b, uint64(ct))
	b = quicvarint.Append(b, uint64(len(payload)))
	b = append(b, payload...)
	return b
}

// TestRelaySkipCapsulesRejectsOversizedCapsule documents bounded server relay skip (UDP-AUDIT-05).
func TestRelaySkipCapsulesRejectsOversizedCapsule(t *testing.T) {
	t.Parallel()
	oversized := make([]byte, skipCapsuleDatagramMaxPayload+1)
	wire := encodeCapsulePayload(capsuleTypeDatagram, oversized)
	err := skipCapsules(quicvarint.NewReader(bytes.NewReader(wire)))
	if err == nil {
		t.Fatal("want error for oversized datagram capsule")
	}
}

// TestRelaySkipCapsulesAllowsSmallDatagramCapsule verifies normal bounded skip path.
func TestRelaySkipCapsulesAllowsSmallDatagramCapsule(t *testing.T) {
	t.Parallel()
	wire := encodeCapsulePayload(capsuleTypeDatagram, []byte{0, 1, 2, 3})
	err := skipCapsules(quicvarint.NewReader(bytes.NewReader(wire)))
	if err != io.EOF && err != nil {
		t.Fatalf("skipCapsules: %v", err)
	}
}

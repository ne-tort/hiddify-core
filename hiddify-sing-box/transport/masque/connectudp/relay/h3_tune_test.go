package relay

import (
	"bytes"
	"io"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
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
	oversized := make([]byte, frame.SkipCapsuleDatagramMaxPayload+1)
	wire := encodeCapsulePayload(http3.CapsuleType(0), oversized)
	err := frame.SkipRequestStreamCapsules(quicvarint.NewReader(bytes.NewReader(wire)))
	if err == nil {
		t.Fatal("want error for oversized datagram capsule")
	}
}

// TestRelaySkipCapsulesAllowsSmallDatagramCapsule verifies normal bounded skip path.
func TestRelaySkipCapsulesAllowsSmallDatagramCapsule(t *testing.T) {
	t.Parallel()
	wire := encodeCapsulePayload(http3.CapsuleType(0), []byte{0, 1, 2, 3})
	err := frame.SkipRequestStreamCapsules(quicvarint.NewReader(bytes.NewReader(wire)))
	if err != io.EOF && err != nil {
		t.Fatalf("SkipRequestStreamCapsules: %v", err)
	}
}

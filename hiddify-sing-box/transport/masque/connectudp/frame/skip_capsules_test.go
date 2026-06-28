package frame

import (
	"bytes"
	"io"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

func appendCapsuleWire(b []byte, ct http3.CapsuleType, payload []byte) []byte {
	b = quicvarint.Append(b, uint64(ct))
	b = quicvarint.Append(b, uint64(len(payload)))
	return append(b, payload...)
}

func TestSkipRequestStreamCapsulesUnknownTypeSilentRFC9297(t *testing.T) {
	t.Parallel()
	unknown := http3.CapsuleType(0xface)
	wire := appendCapsuleWire(nil, unknown, []byte{0xde, 0xad, 0xbe, 0xef})
	err := SkipRequestStreamCapsules(quicvarint.NewReader(bytes.NewReader(wire)))
	if err != io.EOF {
		t.Fatalf("unknown capsule skip: err=%v want EOF", err)
	}
}

func TestSkipRequestStreamCapsulesUnknownThenDatagram(t *testing.T) {
	t.Parallel()
	unknown := http3.CapsuleType(0xbeef)
	dgramPayload := append([]byte{0}, []byte("udp")...)
	wire := appendCapsuleWire(nil, unknown, []byte{1, 2, 3})
	wire = appendCapsuleWire(wire, http3.CapsuleType(0), dgramPayload)
	err := SkipRequestStreamCapsules(quicvarint.NewReader(bytes.NewReader(wire)))
	if err != io.EOF {
		t.Fatalf("skip chain: err=%v want EOF", err)
	}
}

func TestSkipRequestStreamCapsulesRejectsOversizedUnknownDeclaredLength(t *testing.T) {
	t.Parallel()
	unknown := http3.CapsuleType(0xface)
	wire := quicvarint.Append(nil, uint64(unknown))
	wire = quicvarint.Append(wire, uint64(SkipCapsuleNondatagramMaxPayload+1))
	err := SkipRequestStreamCapsules(quicvarint.NewReader(bytes.NewReader(wire)))
	if err == nil {
		t.Fatal("expected oversize unknown capsule error")
	}
	if got := err.Error(); !bytes.Contains([]byte(got), []byte("exceeds")) {
		t.Fatalf("oversize error %q want exceeds", got)
	}
}

func TestSkipRequestStreamCapsulesTruncatedUnknownBody(t *testing.T) {
	t.Parallel()
	unknown := http3.CapsuleType(0xface)
	wire := quicvarint.Append(nil, uint64(unknown))
	wire = quicvarint.Append(wire, 10)
	wire = append(wire, 1, 2, 3, 4)
	err := SkipRequestStreamCapsules(quicvarint.NewReader(bytes.NewReader(wire)))
	if err == nil {
		t.Fatal("expected truncated capsule error")
	}
}

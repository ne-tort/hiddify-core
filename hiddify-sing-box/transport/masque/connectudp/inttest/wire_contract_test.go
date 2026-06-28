package inttest_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	cudpframe "github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

// TestConnectUDPWireContract locks P-UDP RFC-M invariants (W-UDP-0 / §8.5).
func TestConnectUDPWireContract(t *testing.T) {
	t.Parallel()

	t.Run("H3Ctx0SingleBytePrefix", func(t *testing.T) {
		t.Parallel()
		payload, ok, err := cudpframe.ParseHTTPDatagramUDP([]byte{0x00, 0xde, 0xad})
		if err != nil || !ok {
			t.Fatalf("parse: ok=%v err=%v", ok, err)
		}
		if !bytes.Equal(payload, []byte{0xde, 0xad}) {
			t.Fatalf("payload=%v", payload)
		}
	})

	t.Run("H3Ctx0TwoByteVarintPrefix", func(t *testing.T) {
		t.Parallel()
		raw := append([]byte{0x40}, 0x00)
		raw = append(raw, 0xbe, 0xef)
		payload, ok, err := cudpframe.ParseHTTPDatagramUDP(raw)
		if err != nil || !ok {
			t.Fatalf("parse: ok=%v err=%v", ok, err)
		}
		if !bytes.Equal(payload, []byte{0xbe, 0xef}) {
			t.Fatalf("payload=%v", payload)
		}
	})

	t.Run("H3UnknownContextIdDropped", func(t *testing.T) {
		t.Parallel()
		raw := quicvarint.Append(nil, 37)
		raw = append(raw, 0xaa)
		_, ok, err := cudpframe.ParseHTTPDatagramUDP(raw)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if ok {
			t.Fatal("unknown context must be dropped (ok=false)")
		}
	})

	t.Run("H3EmptyPayloadICMPShape", func(t *testing.T) {
		t.Parallel()
		payload, ok, err := cudpframe.ParseHTTPDatagramUDP([]byte{0x00})
		if err != nil || !ok {
			t.Fatalf("empty ctx0 datagram: ok=%v err=%v", ok, err)
		}
		if len(payload) != 0 {
			t.Fatalf("want empty UDP payload, got %d bytes", len(payload))
		}
	})

	t.Run("H2DatagramCapsuleCtx0Roundtrip", func(t *testing.T) {
		t.Parallel()
		udp := []byte("wire-contract")
		var wire bytes.Buffer
		if err := h2c.WriteDatagramCapsule(&wire, udp); err != nil {
			t.Fatal(err)
		}
		ct, cr, err := h2c.ParseCapsule(quicvarint.NewReader(bytes.NewReader(wire.Bytes())))
		if err != nil {
			t.Fatal(err)
		}
		if ct != h2c.CapsuleTypeDatagram {
			t.Fatalf("capsule type %v want DATAGRAM", ct)
		}
		inner, err := io.ReadAll(cr)
		if err != nil {
			t.Fatal(err)
		}
		got, ok, perr := cudpframe.ParseHTTPDatagramUDP(inner)
		if perr != nil || !ok {
			t.Fatalf("inner parse: ok=%v err=%v", ok, perr)
		}
		if !bytes.Equal(got, udp) {
			t.Fatalf("payload mismatch: %q", got)
		}
	})

	t.Run("H2UnknownCapsuleTypeSkippedByParser", func(t *testing.T) {
		t.Parallel()
		var wire bytes.Buffer
		if err := http3.WriteCapsule(&wire, http3.CapsuleType(0x37), []byte("discard")); err != nil {
			t.Fatal(err)
		}
		if err := h2c.WriteDatagramCapsule(&wire, []byte("ok")); err != nil {
			t.Fatal(err)
		}
		r := quicvarint.NewReader(bytes.NewReader(wire.Bytes()))
		ct, cr, err := h2c.ParseCapsule(r)
		if err != nil || ct != h2c.CapsuleType(0x37) {
			t.Fatalf("first capsule: ct=%v err=%v", ct, err)
		}
		if _, err := io.Copy(io.Discard, cr); err != nil {
			t.Fatal(err)
		}
		ct, cr, err = h2c.ParseCapsule(r)
		if err != nil || ct != h2c.CapsuleTypeDatagram {
			t.Fatalf("second capsule: ct=%v err=%v", ct, err)
		}
		inner, err := io.ReadAll(cr)
		if err != nil {
			t.Fatal(err)
		}
		got, ok, perr := cudpframe.ParseHTTPDatagramUDP(inner)
		if perr != nil || !ok || !bytes.Equal(got, []byte("ok")) {
			t.Fatalf("datagram after skip: ok=%v err=%v payload=%q", ok, perr, got)
		}
	})

	t.Run("ConnectUDPRequestProtocol", func(t *testing.T) {
		t.Parallel()
		if cudpframe.RequestProtocol != "connect-udp" {
			t.Fatalf("RequestProtocol=%q want connect-udp", cudpframe.RequestProtocol)
		}
	})
}

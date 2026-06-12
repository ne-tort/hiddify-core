package h2

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"testing"

	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/quic-go/quic-go/quicvarint"
)

func TestMaxCapsulePayloadMTUParityWithH3(t *testing.T) {
	ceilingMax := cip.DatagramCeilingMax()
	if got := MaxCapsulePayload(); got != cip.H2MaxCapsulePayload(ceilingMax) {
		t.Fatalf("MaxCapsulePayload=%d want %d", got, cip.H2MaxCapsulePayload(ceilingMax))
	}
	h3MTU := cip.H3NetstackMTU(ceilingMax)
	h2MTU := cip.H2NetstackMTU(ceilingMax)
	if h2MTU-h3MTU != cip.DatagramSlack {
		t.Fatalf("H2-H3 netstack delta=%d want slack %d", h2MTU-h3MTU, cip.DatagramSlack)
	}
	if MaxCapsulePayload() != ceilingMax+cip.DatagramSlack {
		t.Fatalf("capsule max=%d want ceiling+slack=%d", MaxCapsulePayload(), ceilingMax+cip.DatagramSlack)
	}
	if cip.MaxIPv4Datagram(ceilingMax)+cip.DatagramSlack != ceilingMax {
		t.Fatalf("forwarder max IPv4 + slack must equal ceiling max")
	}
}

func TestParseCapsuleRejectsAstronomicDatagramDeclaredLength(t *testing.T) {
	var hdr bytes.Buffer
	hdr.Write(quicvarint.Append(nil, uint64(CapsuleTypeDatagram)))
	hdr.Write(quicvarint.Append(nil, uint64(MaxCapsulePayload())+1_000_000))
	vr := quicvarint.NewReader(bytes.NewReader(hdr.Bytes()))
	_, _, err := ParseCapsule(vr)
	if !errors.Is(err, ErrOversizedDeclared) {
		t.Fatalf("expected ErrOversizedDeclared, got %v", err)
	}
}

func TestWriteDatagramCapsuleRoundtrip(t *testing.T) {
	var wire bytes.Buffer
	if err := WriteDatagramCapsule(&wire, []byte("z")); err != nil {
		t.Fatal(err)
	}
	ct, cr, err := ParseCapsule(quicvarint.NewReader(bytes.NewReader(wire.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	if ct != CapsuleTypeDatagram {
		t.Fatalf("type=%v want DATAGRAM", ct)
	}
	body, err := io.ReadAll(cr)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 2 || body[0] != 0 || body[1] != 'z' {
		t.Fatalf("body=%v", body)
	}
}

func TestWriteUDPPayloadAsDatagramCapsulesSplitsLargePayload(t *testing.T) {
	total := MaxUDPPayloadPerDatagramCapsule()*2 + 50
	payload := bytes.Repeat([]byte{'a'}, total)
	var wire bytes.Buffer
	if err := WriteUDPPayloadAsDatagramCapsules(&wire, payload); err != nil {
		t.Fatal(err)
	}
	r := quicvarint.NewReader(bytes.NewReader(wire.Bytes()))
	reassembled := make([]byte, 0, total)
	for {
		ct, cr, cerr := ParseCapsule(r)
		if cerr == io.EOF {
			break
		}
		if cerr != nil {
			t.Fatal(cerr)
		}
		if ct != CapsuleTypeDatagram {
			t.Fatalf("type=%v", ct)
		}
		chunk, rerr := io.ReadAll(cr)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if len(chunk) < 1 || chunk[0] != 0 {
			t.Fatalf("bad context id in %v", chunk)
		}
		reassembled = append(reassembled, chunk[1:]...)
	}
	if !bytes.Equal(reassembled, payload) {
		t.Fatalf("reassembled len=%d want %d", len(reassembled), total)
	}
}

func TestCapsuleProtocolHeaderValue(t *testing.T) {
	if v := CapsuleProtocolHeaderValue(); v == "" {
		t.Fatal("empty Capsule-Protocol header value")
	}
}

// TestH2ConnectIPCapsuleRoundtrip verifies CONNECT-IP IPv4 datagrams fit RFC 9297 DATAGRAM capsules on H2.
func TestH2ConnectIPCapsuleRoundtrip(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")
	ipPacket, err := cip.BuildIPv4UDPPacket(src, 53000, dst, 53, []byte("dns-query"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ipPacket) > cip.MaxIPv4Datagram(cip.DatagramCeilingMax()) {
		t.Fatalf("test packet len=%d exceeds forwarder max", len(ipPacket))
	}

	var wire bytes.Buffer
	if err := WriteDatagramCapsule(&wire, ipPacket); err != nil {
		t.Fatal(err)
	}
	ct, cr, err := ParseCapsule(quicvarint.NewReader(bytes.NewReader(wire.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	if ct != CapsuleTypeDatagram {
		t.Fatalf("type=%v want DATAGRAM", ct)
	}
	body, err := io.ReadAll(cr)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 1 || body[0] != 0 {
		t.Fatalf("missing context id prefix: %v", body)
	}
	if !bytes.Equal(body[1:], ipPacket) {
		t.Fatalf("IP packet roundtrip mismatch: got %d bytes want %d", len(body)-1, len(ipPacket))
	}
}

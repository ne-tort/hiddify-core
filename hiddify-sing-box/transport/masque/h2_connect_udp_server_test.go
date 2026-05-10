package masque

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

func TestServeH2ConnectUDPWrapsCapsuleParseError(t *testing.T) {
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	w := httptest.NewRecorder()
	// Truncated capsule / invalid varints must carry the dataplane prefix (parity with client ReadFrom).
	r := &http.Request{Method: http.MethodConnect, Body: io.NopCloser(bytes.NewReader([]byte{0xff}))}
	err = ServeH2ConnectUDP(w, r, uc)
	if err == nil {
		t.Fatal("expected error for corrupt capsule stream")
	}
	if !strings.Contains(err.Error(), "masque h2 dataplane connect-udp server capsule:") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServeH2ConnectUDPRejectsOversizedDatagramCapsule(t *testing.T) {
	// Capsule value (HTTP Datagram payload) one byte over the same limit as client ReadFrom / ServeH2 parity.
	inner := make([]byte, h2ConnectUDPMaxCapsulePayload+1)
	inner[0] = 0
	var wire bytes.Buffer
	if err := http3.WriteCapsule(&wire, capsuleTypeDatagram, inner); err != nil {
		t.Fatal(err)
	}
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()

	w := httptest.NewRecorder()
	r := &http.Request{Method: http.MethodConnect, Body: io.NopCloser(bytes.NewReader(wire.Bytes()))}
	err = ServeH2ConnectUDP(w, r, uc)
	if err == nil {
		t.Fatal("expected error for oversized DATAGRAM capsule body")
	}
	if !strings.Contains(err.Error(), "DATAGRAM capsule payload exceeds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServeH2ConnectUDPRejectsOversizedNondatagramCapsule(t *testing.T) {
	inner := make([]byte, h2ConnectUDPNondatagramMaxCapsulePayload+1)
	var wire bytes.Buffer
	if err := http3.WriteCapsule(&wire, http3.CapsuleType(9), inner); err != nil {
		t.Fatal(err)
	}
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()

	w := httptest.NewRecorder()
	r := &http.Request{Method: http.MethodConnect, Body: io.NopCloser(bytes.NewReader(wire.Bytes()))}
	err = ServeH2ConnectUDP(w, r, uc)
	if err == nil {
		t.Fatal("expected error for oversized non-DATAGRAM capsule body")
	}
	if !strings.Contains(err.Error(), "non-datagram capsule exceeds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServeH2ConnectUDPGracefulEOFDoesNotReturnClosedConnError(t *testing.T) {
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()

	w := httptest.NewRecorder()
	r := &http.Request{Method: http.MethodConnect, Body: io.NopCloser(bytes.NewReader(nil))}
	err = ServeH2ConnectUDP(w, r, uc)
	if err != nil {
		t.Fatalf("expected clean shutdown on request EOF, got: %v", err)
	}
}

func TestWriteUDPPayloadAsH2DatagramCapsulesEmpty(t *testing.T) {
	var wire bytes.Buffer
	if err := writeUDPPayloadAsH2DatagramCapsules(&wire, nil, nil); err != nil {
		t.Fatal(err)
	}
	ct, cr, err := parseH2ConnectUDPCapsule(quicvarint.NewReader(bytes.NewReader(wire.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	if ct != capsuleTypeDatagram {
		t.Fatalf("unexpected capsule type %v", ct)
	}
	raw, err := io.ReadAll(cr)
	if err != nil {
		t.Fatal(err)
	}
	payload, ok, perr := ParseMasqueHTTPDatagramUDP(raw)
	if perr != nil || !ok {
		t.Fatalf("unexpected parse: ok=%v err=%v", ok, perr)
	}
	if len(payload) != 0 {
		t.Fatalf("expected empty udp payload inside HTTP datagram, got len=%d", len(payload))
	}
}

func TestWriteUDPPayloadAsH2DatagramCapsulesSplitsLargePayload(t *testing.T) {
	total := h2ConnectUDPMaxUDPPayloadPerDatagramCapsule*2 + 50
	payload := bytes.Repeat([]byte{'z'}, total)
	var wire bytes.Buffer
	if err := writeUDPPayloadAsH2DatagramCapsules(&wire, nil, payload); err != nil {
		t.Fatal(err)
	}
	r := quicvarint.NewReader(bytes.NewReader(wire.Bytes()))
	var reassembled []byte
	for {
		ct, cr, err := parseH2ConnectUDPCapsule(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("parse capsule: %v", err)
		}
		if ct != capsuleTypeDatagram {
			t.Fatalf("unexpected capsule type %v", ct)
		}
		raw, err := io.ReadAll(cr)
		if err != nil {
			t.Fatal(err)
		}
		p, ok, perr := ParseMasqueHTTPDatagramUDP(raw)
		if perr != nil || !ok {
			t.Fatalf("ParseMasqueHTTPDatagramUDP: ok=%v err=%v", ok, perr)
		}
		reassembled = append(reassembled, p...)
	}
	if len(reassembled) != total {
		t.Fatalf("reassembled len=%d want %d", len(reassembled), total)
	}
	if !bytes.Equal(reassembled, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestWriteUDPH2ConnectDatagramCapsuleZeroLengthUDP(t *testing.T) {
	var buf bytes.Buffer
	if err := writeUDPH2ConnectDatagramCapsule(&buf, nil, nil); err != nil {
		t.Fatal(err)
	}
	ct, cr, err := parseH2ConnectUDPCapsule(quicvarint.NewReader(bytes.NewReader(buf.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	if ct != capsuleTypeDatagram {
		t.Fatalf("unexpected capsule type %v", ct)
	}
	raw, err := io.ReadAll(cr)
	if err != nil {
		t.Fatal(err)
	}
	payload, ok, perr := ParseMasqueHTTPDatagramUDP(raw)
	if perr != nil || !ok {
		t.Fatalf("unexpected parse: ok=%v err=%v", ok, perr)
	}
	if len(payload) != 0 {
		t.Fatalf("expected empty udp payload inside HTTP datagram, got %v", payload)
	}
}

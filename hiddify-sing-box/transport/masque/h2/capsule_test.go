package h2

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/quic-go/quic-go/quicvarint"
)

type flushCountResponseWriter struct {
	mu      sync.Mutex
	hdr     http.Header
	body    bytes.Buffer
	flushes atomic.Int32
}

func (w *flushCountResponseWriter) Header() http.Header {
	if w.hdr == nil {
		w.hdr = make(http.Header)
	}
	return w.hdr
}

func (w *flushCountResponseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.body.Write(p)
}

func (w *flushCountResponseWriter) Flush() {
	w.flushes.Add(1)
}

// TestWriteDatagramCapsulePerCapsuleFlush (G54/L1a-H1): each WriteDatagramCapsule flushes once.
func TestWriteDatagramCapsulePerCapsuleFlush(t *testing.T) {
	rec := &flushCountResponseWriter{}
	for i := 0; i < 3; i++ {
		if err := WriteDatagramCapsule(rec, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if got := rec.flushes.Load(); got != 3 {
		t.Fatalf("flushes=%d want 3 (one per capsule)", got)
	}
}

// TestAppendUDPPayloadAsDatagramCapsulesNoFlush (G54): append path must not flush mid-batch.
func TestAppendUDPPayloadAsDatagramCapsulesNoFlush(t *testing.T) {
	rec := &flushCountResponseWriter{}
	payload := bytes.Repeat([]byte("u"), MaxUDPPayloadPerDatagramCapsule()*2+10)
	if err := AppendUDPPayloadAsDatagramCapsules(rec, payload); err != nil {
		t.Fatal(err)
	}
	if got := rec.flushes.Load(); got != 0 {
		t.Fatalf("append flushes=%d want 0", got)
	}
}

// TestWriteUDPPayloadAsDatagramCapsulesTerminalFlush (G54): batched write flushes once at end.
func TestWriteUDPPayloadAsDatagramCapsulesTerminalFlush(t *testing.T) {
	rec := &flushCountResponseWriter{}
	payload := bytes.Repeat([]byte("u"), MaxUDPPayloadPerDatagramCapsule()*2+10)
	if err := WriteUDPPayloadAsDatagramCapsules(rec, payload); err != nil {
		t.Fatal(err)
	}
	if got := rec.flushes.Load(); got != 1 {
		t.Fatalf("flushes=%d want 1 terminal flush", got)
	}
}

func TestParseNextDatagramCapsuleWireRoundTrip(t *testing.T) {
	var wire bytes.Buffer
	payload := bytes.Repeat([]byte("z"), 512)
	if err := AppendUDPPayloadAsDatagramCapsules(&wire, payload); err != nil {
		t.Fatal(err)
	}
	buf := wire.Bytes()
	var reassembled []byte
	for len(buf) > 0 {
		inner, n, err := ParseNextDatagramCapsuleWire(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatal("expected consumed bytes")
		}
		buf = buf[n:]
		if inner == nil {
			continue
		}
		if inner[0] != 0 {
			t.Fatalf("expected context 0, got %d", inner[0])
		}
		reassembled = append(reassembled, inner[1:]...)
	}
	if !bytes.Equal(reassembled, payload) {
		t.Fatalf("reassembled len=%d want %d", len(reassembled), len(payload))
	}
}

func TestParseNextDatagramCapsuleWireIncomplete(t *testing.T) {
	var wire bytes.Buffer
	if err := AppendDatagramCapsuleWire(&wire, []byte("x")); err != nil {
		t.Fatal(err)
	}
	trunc := wire.Bytes()[:wire.Len()-2]
	_, n, err := ParseNextDatagramCapsuleWire(trunc)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("consumed=%d want 0 on truncated wire", n)
	}
}

func TestReadCapsulePayloadPooled(t *testing.T) {
	var wire bytes.Buffer
	if err := AppendDatagramCapsuleWire(&wire, []byte("udp")); err != nil {
		t.Fatal(err)
	}
	ct, cr, err := ParseCapsule(quicvarint.NewReader(bytes.NewReader(wire.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	if ct != CapsuleTypeDatagram {
		t.Fatalf("type=%v", ct)
	}
	body, release, err := ReadCapsulePayload(cr)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if string(body) != "\x00udp" {
		t.Fatalf("body=%q", body)
	}
}

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

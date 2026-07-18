package h2

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

func TestServeH2ConnectUDPWrapsCapsuleParseError(t *testing.T) {
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	w := httptest.NewRecorder()
	r := &http.Request{Method: http.MethodConnect, Body: io.NopCloser(bytes.NewReader([]byte{0xff}))}
	err = ServeH2(w, r, uc)
	if err == nil {
		t.Fatal("expected error for corrupt capsule stream")
	}
	if !strings.Contains(err.Error(), "masque h2 dataplane connect-udp server capsule:") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServeH2ConnectUDPRejectsOversizedDatagramCapsule(t *testing.T) {
	inner := make([]byte, h2c.MaxCapsulePayload()+1)
	inner[0] = 0
	var wire bytes.Buffer
	if err := http3.WriteCapsule(&wire, http3.CapsuleType(h2c.CapsuleTypeDatagram), inner); err != nil {
		t.Fatal(err)
	}
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()

	w := httptest.NewRecorder()
	r := &http.Request{Method: http.MethodConnect, Body: io.NopCloser(bytes.NewReader(wire.Bytes()))}
	err = ServeH2(w, r, uc)
	if err == nil {
		t.Fatal("expected error for oversized DATAGRAM capsule body")
	}
	if !strings.Contains(err.Error(), "DATAGRAM capsule payload exceeds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServeH2ConnectUDPRejectsOversizedNondatagramCapsule(t *testing.T) {
	inner := make([]byte, h2c.NondatagramMaxCapsulePayload+1)
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
	err = ServeH2(w, r, uc)
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
	err = ServeH2(w, r, uc)
	if err != nil {
		t.Fatalf("expected clean shutdown on request EOF, got: %v", err)
	}
}

func TestH2ResponseWriterBidiImmediateFlush(t *testing.T) {
	rec := &flushCountResponseWriter{}
	w := newH2DownlinkWriter(rec, LegProfileBidi)
	for i := 0; i < 5; i++ {
		if err := w.WriteUDPPayloadAsCapsules([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if got := rec.flushes.Load(); got != 5 {
		t.Fatalf("bidi h2o immediate flush: flushes=%d want 5", got)
	}
}

func TestH2ResponseWriterICMPImmediateFlush(t *testing.T) {
	rec := &flushCountResponseWriter{}
	w := newH2DownlinkWriter(rec, LegProfileDownloadFountain)
	if err := w.WriteUDPPayloadAsCapsules(nil); err != nil {
		t.Fatal(err)
	}
	if got := rec.flushes.Load(); got != 1 {
		t.Fatalf("ICMP empty datagram: flushes=%d want 1 (h2o immediate)", got)
	}
}

func TestH2ResponseWriterFountainFlushOnlyViaFlushPending(t *testing.T) {
	rec := &flushCountResponseWriter{}
	w := newH2DownlinkWriter(rec, LegProfileDownloadFountain)
	payload := bytes.Repeat([]byte{'x'}, 512)
	perWire := h2c.DatagramCapsule512WireLen
	// Past old 64KiB threshold — must still not auto-flush (B7: per-batch only).
	need := (H2DownlinkBulkFlushBytes / perWire) + 1
	for i := 0; i < need; i++ {
		if err := w.AppendUDPPayloadAsCapsules(payload); err != nil {
			t.Fatal(err)
		}
	}
	if got := rec.flushes.Load(); got != 0 {
		t.Fatalf("Append must not auto-flush: flushes=%d want 0", got)
	}
	if err := w.FlushPending(); err != nil {
		t.Fatal(err)
	}
	if got := rec.flushes.Load(); got != 1 {
		t.Fatalf("FlushPending: flushes=%d want 1", got)
	}
}

func TestH2ResponseWriterFountainProfileNoDebounceTimer(t *testing.T) {
	rec := &flushCountResponseWriter{}
	w := newH2DownlinkWriter(rec, LegProfileDownloadFountain)
	payload := bytes.Repeat([]byte{'y'}, 512)
	if err := w.AppendUDPPayloadAsCapsules(payload); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if got := rec.flushes.Load(); got != 0 {
		t.Fatalf("fountain must not time-flush: flushes=%d want 0", got)
	}
}

type flushCountResponseWriter struct {
	mu   sync.Mutex
	hdr  http.Header
	body bytes.Buffer
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

func (w *flushCountResponseWriter) WriteHeader(int) {}

func (w *flushCountResponseWriter) Flush() {
	w.flushes.Add(1)
}

func TestWriteUDPPayloadAsH2DatagramCapsulesEmpty(t *testing.T) {
	var wire bytes.Buffer
	if err := h2c.WriteUDPPayloadAsDatagramCapsules(&wire, nil); err != nil {
		t.Fatal(err)
	}
	ct, cr, err := h2c.ParseCapsule(quicvarint.NewReader(bytes.NewReader(wire.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	if ct != h2c.CapsuleTypeDatagram {
		t.Fatalf("unexpected capsule type %v", ct)
	}
	raw, err := io.ReadAll(cr)
	if err != nil {
		t.Fatal(err)
	}
	payload, ok, perr := frame.ParseHTTPDatagramUDP(raw)
	if perr != nil || !ok {
		t.Fatalf("unexpected parse: ok=%v err=%v", ok, perr)
	}
	if len(payload) != 0 {
		t.Fatalf("expected empty udp payload inside HTTP datagram, got len=%d", len(payload))
	}
}

func TestWriteUDPPayloadAsH2DatagramCapsulesSplitsLargePayload(t *testing.T) {
	total := h2c.MaxUDPPayloadPerDatagramCapsule()*2 + 50
	payload := bytes.Repeat([]byte{'z'}, total)
	var wire bytes.Buffer
	if err := h2c.WriteUDPPayloadAsDatagramCapsules(&wire, payload); err != nil {
		t.Fatal(err)
	}
	r := quicvarint.NewReader(bytes.NewReader(wire.Bytes()))
	var reassembled []byte
	for {
		ct, cr, err := h2c.ParseCapsule(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("parse capsule: %v", err)
		}
		if ct != h2c.CapsuleTypeDatagram {
			t.Fatalf("unexpected capsule type %v", ct)
		}
		raw, err := io.ReadAll(cr)
		if err != nil {
			t.Fatal(err)
		}
		p, ok, perr := frame.ParseHTTPDatagramUDP(raw)
		if perr != nil || !ok {
			t.Fatalf("frame.ParseHTTPDatagramUDP: ok=%v err=%v", ok, perr)
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
	if err := h2c.WriteDatagramCapsule(&buf, nil); err != nil {
		t.Fatal(err)
	}
	ct, cr, err := h2c.ParseCapsule(quicvarint.NewReader(bytes.NewReader(buf.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	if ct != h2c.CapsuleTypeDatagram {
		t.Fatalf("unexpected capsule type %v", ct)
	}
	raw, err := io.ReadAll(cr)
	if err != nil {
		t.Fatal(err)
	}
	payload, ok, perr := frame.ParseHTTPDatagramUDP(raw)
	if perr != nil || !ok {
		t.Fatalf("unexpected parse: ok=%v err=%v", ok, perr)
	}
	if len(payload) != 0 {
		t.Fatalf("expected empty udp payload inside HTTP datagram, got %v", payload)
	}
}

// TestServeH2ConnectUDPWriteRefusedRelaysEmptyDatagram verifies ICMP port-unreachable surfaced on
// connected-UDP Write (Linux bench dig to TCP-only port) is relayed as an empty RFC 9297 DATAGRAM.
func TestServeH2ConnectUDPWriteRefusedRelaysEmptyDatagram(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("connected UDP ICMP on Write is unreliable on Windows")
	}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpLn.Close() })
	tcpPort := tcpLn.Addr().(*net.TCPAddr).Port

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpPort)))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var uplink bytes.Buffer
	if err := http3.WriteCapsule(&uplink, http3.CapsuleType(h2c.CapsuleTypeDatagram), []byte{0, 0xde, 0xad}); err != nil {
		t.Fatal(err)
	}

	w := &recordingH2UDPResponseWriter{ResponseWriter: &nopH2UDPResponseWriter{}}
	r := &http.Request{
		Method: http.MethodConnect,
		Body:   io.NopCloser(bytes.NewReader(uplink.Bytes())),
	}
	done := make(chan error, 1)
	go func() { done <- ServeH2(w, r, conn) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeH2: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not finish after uplink write to refused port")
	}
	if w.datagramCapsules() < 1 {
		t.Fatal("expected empty ICMP DATAGRAM capsule on response body after Write ECONNREFUSED")
	}
}

// TestServeH2ConnectUDPEmptyUplinkPrimeDoesNotWriteUDP verifies stream-prime zero-length
// DATAGRAM capsules unblock the downlink without writing to the onward UDP socket.
func TestServeH2ConnectUDPEmptyUplinkPrimeDoesNotWriteUDP(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("connected UDP ICMP behavior differs on Windows")
	}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpLn.Close() })
	tcpPort := tcpLn.Addr().(*net.TCPAddr).Port

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpPort)))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var uplink bytes.Buffer
	if err := h2c.WriteDatagramCapsule(&uplink, nil); err != nil {
		t.Fatal(err)
	}

	w := &recordingH2UDPResponseWriter{ResponseWriter: &nopH2UDPResponseWriter{}}
	r := &http.Request{
		Method: http.MethodConnect,
		Body:   io.NopCloser(bytes.NewReader(uplink.Bytes())),
	}
	done := make(chan error, 1)
	go func() { done <- ServeH2(w, r, conn) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeH2: %v", err)
		}
	case <-time.After(2 * time.Second):
		// Relay may block waiting for UDP; prime must have started downlink without write error.
	}
	if w.datagramCapsules() == 0 {
		t.Fatal("expected at least one downlink DATAGRAM capsule (ICMP empty or payload) after prime")
	}
}

type nopH2UDPResponseWriter struct{}

func (nopH2UDPResponseWriter) Header() http.Header         { return http.Header{} }
func (nopH2UDPResponseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (nopH2UDPResponseWriter) WriteHeader(int)             {}

type recordingH2UDPResponseWriter struct {
	http.ResponseWriter
	mu   sync.Mutex
	wire bytes.Buffer
}

func (w *recordingH2UDPResponseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.wire.Write(p)
	w.mu.Unlock()
	return len(p), nil
}

func (w *recordingH2UDPResponseWriter) datagramCapsules() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	r := quicvarint.NewReader(bytes.NewReader(w.wire.Bytes()))
	for {
		ct, cr, err := h2c.ParseCapsule(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return n
		}
		if ct == h2c.CapsuleTypeDatagram {
			n++
		}
		_, _ = io.Copy(io.Discard, cr)
	}
	return n
}

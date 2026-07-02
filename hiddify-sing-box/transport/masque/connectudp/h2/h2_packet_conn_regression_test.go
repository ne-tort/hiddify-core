package h2

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	"github.com/sagernet/sing-box/transport/masque/connectudp/split"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

func TestParseHTTPDatagramUDPZeroContext(t *testing.T) {
	p, ok, err := frame.ParseHTTPDatagramUDP([]byte{0, 'a', 'b'})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, []byte("ab"), p)
}

func TestWriteMasqueCapsuleUDPFrame(t *testing.T) {
	var buf bytes.Buffer
	dgram := []byte{0, 'z'}
	require.NoError(t, http3.WriteCapsule(&buf, http3.CapsuleType(h2c.CapsuleTypeDatagram), dgram))
	require.Greater(t, buf.Len(), 3)
}

// Regression: bogus declared capsule length must be rejected without draining the advertised span into Discard
// (http3.ParseCapsule + io.Copy(io.Discard, reader) admitted hostiles before this hard cap).
func TestParseH2ConnectUDPCapsuleRejectsAstronomicDatagramDeclaredLength(t *testing.T) {
	var hdr bytes.Buffer
	hdr.Write(quicvarint.Append(nil, uint64(http3.CapsuleType(h2c.CapsuleTypeDatagram))))
	hdr.Write(quicvarint.Append(nil, uint64(h2c.MaxCapsulePayload())+1_000_000))
	vr := quicvarint.NewReader(bytes.NewReader(hdr.Bytes()))
	_, _, err := h2c.ParseCapsule(vr)
	require.Error(t, err)
	require.ErrorIs(t, err, h2c.ErrOversizedDeclared)
	require.Contains(t, err.Error(), "DATAGRAM capsule payload exceeds")
}

// TestPacketConnSkipsMalformedHTTPDatagramThenReadsValid verifies that a non-DATAGRAM capsule whose
// value exceeds the DATAGRAM MTU cap is skipped (RFC 9297 allows other capsule types on the stream)
// rather than being mis-parsed as an oversized DATAGRAM payload.
// Regression: malformed HTTP Datagram payload inside a well-formed DATAGRAM capsule must be dropped
// like masque-go proxiedConn.ReadFrom / parseProxiedDatagramPayload (do not Close or fail the relay).
func TestPacketConnSkipsMalformedHTTPDatagramThenReadsValid(t *testing.T) {
	var wire bytes.Buffer
	// Truncated 2-byte context varint prefix (0x40 >> 6 == 1) — parse returns (_, false, io.EOF).
	require.NoError(t, http3.WriteCapsule(&wire, http3.CapsuleType(h2c.CapsuleTypeDatagram), []byte{0x40}))
	require.NoError(t, http3.WriteCapsule(&wire, http3.CapsuleType(h2c.CapsuleTypeDatagram), []byte{0, 'z'}))

	c := NewPacketConn(PacketConnConfig{
		Resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(wire.Bytes()))},
		RemoteAddr: NewUDPAddr("127.0.0.1:1"),
	})
	buf := make([]byte, 64)
	n, _, err := c.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, byte('z'), buf[0])
	require.False(t, c.IsClosed())
}

// Regression: io.EOF must be detected with errors.Is so a wrapped clean shutdown does not look like
// capsule mis-framing (which closes the tunnel via ReadFrom).
type h2UDPReadReturnErr struct{ err error }

func (r h2UDPReadReturnErr) Read(p []byte) (int, error) { return 0, r.err }

func TestPacketConnReadFromCleanEOFWrapped(t *testing.T) {
	wrapped := fmt.Errorf("upstream: %w", io.EOF)
	c := NewPacketConn(PacketConnConfig{
		Resp: &http.Response{Body: io.NopCloser(h2UDPReadReturnErr{err: wrapped})},
	})
	_, _, err := c.ReadFrom(make([]byte, 8))
	require.ErrorIs(t, err, io.EOF)
	require.False(t, c.IsClosed())
}

func TestPacketConnSkipsLargeNonDatagramCapsule(t *testing.T) {
	var wire bytes.Buffer
	large := make([]byte, h2c.MaxCapsulePayload()+100)
	require.NoError(t, http3.WriteCapsule(&wire, http3.CapsuleType(1), large))
	dgram := []byte{0, 'x'}
	require.NoError(t, http3.WriteCapsule(&wire, http3.CapsuleType(h2c.CapsuleTypeDatagram), dgram))

	c := NewPacketConn(PacketConnConfig{
		Resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(wire.Bytes()))},
		RemoteAddr: NewUDPAddr("127.0.0.1:1"),
	})
	buf := make([]byte, 64)
	n, _, err := c.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, byte('x'), buf[0])
}

// Regression: corrupt capsule framing after CONNECT-UDP closes the tunnel (stream stays misaligned).
func TestPacketConnClosesOnTruncatedCapsulePrefix(t *testing.T) {
	var hdr bytes.Buffer
	hdr.Write(quicvarint.Append(nil, uint64(http3.CapsuleType(h2c.CapsuleTypeDatagram))))
	// truncated length varint — ParseCapsule parity expects UnexpectedEOF, not silent EOF
	c := NewPacketConn(PacketConnConfig{
		Resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(hdr.Bytes()))},
		RemoteAddr: NewUDPAddr("127.0.0.1:1"),
	})
	buf := make([]byte, 64)
	n, _, err := c.ReadFrom(buf)
	if err == nil {
		t.Fatal("expected error")
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes read, got %d", n)
	}
	if !c.IsClosed() {
		t.Fatal("expected PacketConn closed after capsule parse failure")
	}
}

// Regression: failed upload after CONNECT must close the PacketConn like read-side capsule faults.
func TestPacketConnClosesOnWriteBodyError(t *testing.T) {
	pr, pw := io.Pipe()
	_ = pr.CloseWithError(errors.New("test closed read side"))

	c := NewPacketConn(PacketConnConfig{ReqBody: pw})
	payload := bytes.Repeat([]byte{42}, testUploadCoalesceThreshold)
	n, err := c.WriteTo(payload, nil)
	require.Error(t, err)
	require.Equal(t, 0, n)
	require.Contains(t, err.Error(), "write body")
	require.True(t, c.IsClosed())
}

type eofWriteCloser struct{}

func (eofWriteCloser) Write([]byte) (int, error) { return 0, io.EOF }
func (eofWriteCloser) Close() error              { return nil }

// Plain io.EOF on request-body write mirrors ReadFrom when the CONNECT response body ends: no Close(),
// no dataplane wrapper (http_layer_fallback / classifiers stay off normal half-close semantics).
func TestPacketConnWriteToCleanEOFWithoutClose(t *testing.T) {
	c := NewPacketConn(PacketConnConfig{
		ReqBody: eofWriteCloser{},
	})
	payload := bytes.Repeat([]byte{1, 2, 3}, testUploadCoalesceThreshold/3+1)
	n, err := c.WriteTo(payload, nil)
	require.Equal(t, 0, n)
	require.ErrorIs(t, err, io.EOF)
	require.False(t, c.IsClosed())
}

type errClosedPipeWriteCloser struct{}

func (errClosedPipeWriteCloser) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (errClosedPipeWriteCloser) Close() error              { return nil }

func TestPacketConnWriteToCleanErrClosedPipeWithoutClose(t *testing.T) {
	c := NewPacketConn(PacketConnConfig{
		ReqBody: errClosedPipeWriteCloser{},
	})
	payload := bytes.Repeat([]byte{1, 2, 3}, testUploadCoalesceThreshold/3+1)
	n, err := c.WriteTo(payload, nil)
	require.Equal(t, 0, n)
	require.ErrorIs(t, err, io.ErrClosedPipe)
	require.False(t, c.IsClosed())
}

type udpCapsuleCaptureWriteCloser struct{ buf bytes.Buffer }

func (c *udpCapsuleCaptureWriteCloser) Write(p []byte) (int, error) {
	return c.buf.Write(p)
}

func (c *udpCapsuleCaptureWriteCloser) Close() error { return nil }

// Parity with third_party masque-go proxiedConn WriteTo(minCap=1 on empty payloads): CONNECT-UDP H2 must
// serialize a DATAGRAM capsule for zero-length UDP, not silently drop egress.
func TestPacketConnWriteToEmptyEmitCapsule(t *testing.T) {
	cap := &udpCapsuleCaptureWriteCloser{}
	c := NewPacketConn(PacketConnConfig{ReqBody: cap})

	n, err := c.WriteTo([]byte(nil), nil)
	require.NoError(t, err)
	require.Zero(t, n)
	require.NotEmpty(t, cap.buf.Bytes())

	ct, cr, err := h2c.ParseCapsule(quicvarint.NewReader(bytes.NewReader(cap.buf.Bytes())))
	require.NoError(t, err)
	require.Equal(t, h2c.CapsuleTypeDatagram, ct)
	raw, err := io.ReadAll(cr)
	require.NoError(t, err)
	payload, ok, perr := frame.ParseHTTPDatagramUDP(raw)
	require.NoError(t, perr)
	require.True(t, ok)
	require.Empty(t, payload)
}

// Regression: one WriteTo must not emit a single DATAGRAM capsule whose HTTP Datagram exceeds
// h2c.MaxCapsulePayload() (server uplink rejects; parity with ServeH2 downlink splitter).
func TestPacketConnWriteToSplitsLargePayloadIntoRFC9297Capsules(t *testing.T) {
	total := h2c.MaxUDPPayloadPerDatagramCapsule()*2 + 50
	payload := bytes.Repeat([]byte{'q'}, total)
	capWC := &udpCapsuleCaptureWriteCloser{}
	c := NewPacketConn(PacketConnConfig{ReqBody: capWC})

	n, err := c.WriteTo(payload, nil)
	require.NoError(t, err)
	require.Equal(t, total, n)
	require.NoError(t, c.Close())

	r := quicvarint.NewReader(bytes.NewReader(capWC.buf.Bytes()))
	var reassembled []byte
	for {
		ct, cr, cerr := h2c.ParseCapsule(r)
		if cerr != nil {
			if cerr == io.EOF {
				break
			}
			require.NoError(t, cerr)
		}
		require.Equal(t, h2c.CapsuleTypeDatagram, ct)
		raw, rerr := io.ReadAll(cr)
		require.NoError(t, rerr)
		pl, ok, perr := frame.ParseHTTPDatagramUDP(raw)
		require.NoError(t, perr)
		require.True(t, ok)
		reassembled = append(reassembled, pl...)
	}
	require.Equal(t, payload, reassembled)
}

func TestPacketConnRejectsOversizedNondatagramCapsule(t *testing.T) {
	var wire bytes.Buffer
	big := make([]byte, h2c.NondatagramMaxCapsulePayload+1)
	require.NoError(t, http3.WriteCapsule(&wire, http3.CapsuleType(7), big))

	c := NewPacketConn(PacketConnConfig{
		Resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(wire.Bytes()))},
		RemoteAddr: NewUDPAddr("127.0.0.1:1"),
	})
	buf := make([]byte, 64)
	n, _, err := c.ReadFrom(buf)
	require.Error(t, err)
	require.Equal(t, 0, n)
	require.Contains(t, err.Error(), "non-datagram capsule exceeds")
	require.True(t, c.IsClosed())
}

// net.PacketConn allows concurrent method calls; serialized ReadFrom avoids concurrent reads on the shared response body reader.
func TestPacketConnConcurrentReadFromSerializesReads(t *testing.T) {
	var wire bytes.Buffer
	for _, b := range []byte{'a', 'b'} {
		dgram := []byte{0, b}
		require.NoError(t, http3.WriteCapsule(&wire, http3.CapsuleType(h2c.CapsuleTypeDatagram), dgram))
	}
	c := NewPacketConn(PacketConnConfig{
		Resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(wire.Bytes()))},
		RemoteAddr: NewUDPAddr("192.0.2.1:53"),
	})
	type readRes struct {
		n   int
		b   byte
		err error
	}
	ch := make(chan readRes, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 8)
			n, _, err := c.ReadFrom(buf)
			var b byte
			if n > 0 {
				b = buf[0]
			}
			ch <- readRes{n: n, b: b, err: err}
		}()
	}
	wg.Wait()
	close(ch)
	var got []byte
	for r := range ch {
		require.NoError(t, r.err)
		require.Equal(t, 1, r.n)
		got = append(got, r.b)
	}
	require.ElementsMatch(t, []byte{'a', 'b'}, got)
}

func TestPacketConnReadFromEmptyDatagramICMPRefused(t *testing.T) {
	var wb bytes.Buffer
	if err := h2c.WriteDatagramCapsule(&wb, nil); err != nil {
		t.Fatal(err)
	}
	c := NewPacketConn(PacketConnConfig{
		Resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(wb.Bytes()))},
		RemoteAddr: NewUDPAddr("192.0.2.3:5201"),
	})
	n, _, err := c.ReadFrom(make([]byte, 64))
	require.Equal(t, 0, n)
	require.ErrorIs(t, err, split.ErrPortUnreachable)
}

func peelUploadPendingCompleteCapsules(pending []byte, maxWire int) (wire, rest []byte) {
	consumed := 0
	for consumed < len(pending) {
		if consumed >= maxWire {
			break
		}
		_, n, err := h2c.ParseNextDatagramCapsuleWire(pending[consumed:])
		if err != nil || n == 0 {
			break
		}
		if consumed+n > maxWire {
			break
		}
		consumed += n
	}
	if consumed == 0 {
		return nil, pending
	}
	return append([]byte(nil), pending[:consumed]...), append([]byte(nil), pending[consumed:]...)
}

// TestPeelUploadPendingCompleteCapsulesNeverSplits documents that bidi upload interleave
// must peel only full RFC9297 capsules (byte-offset peel corrupts the wire stream).
func TestPeelUploadPendingCompleteCapsulesNeverSplits(t *testing.T) {
	var buf bytes.Buffer
	for i := 0; i < 10; i++ {
		require.NoError(t, h2c.AppendDatagramCapsuleWire(&buf, []byte{byte(i), byte(i + 1)}))
	}
	pending := buf.Bytes()
	wire, rest := peelUploadPendingCompleteCapsules(pending, 20)
	require.NotEmpty(t, wire)
	require.NotEmpty(t, rest)
	require.Less(t, len(wire), len(pending))
	for len(wire) > 0 {
		_, n, err := h2c.ParseNextDatagramCapsuleWire(wire)
		require.NoError(t, err)
		require.Greater(t, n, 0)
		wire = wire[n:]
	}
	_, n, err := h2c.ParseNextDatagramCapsuleWire(rest)
	require.NoError(t, err)
	require.Greater(t, n, 0)
}

// TestH2PacketConnAdaptiveUploadInteractiveFlush verifies duplex interactive upload flushes each
// WriteTo immediately (no coalesce timer deferral) when bulk mode is not armed.
func TestH2PacketConnAdaptiveUploadInteractiveFlush(t *testing.T) {
	var downlink bytes.Buffer
	dgram := []byte{0, 'z'}
	require.NoError(t, http3.WriteCapsule(&downlink, http3.CapsuleType(h2c.CapsuleTypeDatagram), dgram))

	capWC := &udpCapsuleCaptureWriteCloser{}
	c := NewPacketConn(PacketConnConfig{
		Resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(downlink.Bytes()))},
		ReqBody:    capWC,
		RemoteAddr: NewUDPAddr("127.0.0.1:53"),
		LegProfile: LegProfileDownloadFountain,
	})
	buf := make([]byte, 8)
	n, _, err := c.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, byte('z'), buf[0])

	c.duplexActive.Store(true)
	capWC.buf.Reset()
	payload := bytes.Repeat([]byte{'u'}, 512)
	wn, err := c.WriteTo(payload, nil)
	require.NoError(t, err)
	require.Equal(t, len(payload), wn)
	require.NotEmpty(t, capWC.buf.Bytes(), "interactive duplex upload must flush without coalesce timer")

	ct, cr, err := h2c.ParseCapsule(quicvarint.NewReader(bytes.NewReader(capWC.buf.Bytes())))
	require.NoError(t, err)
	require.Equal(t, h2c.CapsuleTypeDatagram, ct)
	raw, err := io.ReadAll(cr)
	require.NoError(t, err)
	got, ok, perr := frame.ParseHTTPDatagramUDP(raw)
	require.NoError(t, perr)
	require.True(t, ok)
	require.Equal(t, payload, got)
}

// TestDownlinkQueueSurvivesPendingRealloc verifies queued UDP survives pending trim + append (h2o scan loop).
func TestDownlinkQueueSurvivesPendingRealloc(t *testing.T) {
	c := NewPacketConn(PacketConnConfig{
		Resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(nil))},
		RemoteAddr: NewUDPAddr("127.0.0.1:1"),
	})
	first := bytes.Repeat([]byte{'a'}, 512)
	second := bytes.Repeat([]byte{'b'}, 512)
	w1 := appendDatagramCapsule512WireForTest(t, first)
	w2 := appendDatagramCapsule512WireForTest(t, second)
	c.downlinkPending = append(c.downlinkPending[:0], w1...)
	buf := make([]byte, 512)
	n, _, err := c.tryParseOneDatagramInto(buf)
	require.NoError(t, err)
	require.Equal(t, 512, n)
	require.Equal(t, first, buf)
	c.downlinkPending = append(c.downlinkPending, w2...)
	n, _, err = c.tryParseOneDatagramInto(buf)
	require.NoError(t, err)
	require.Equal(t, 512, n)
	require.Equal(t, second, buf)
}

func appendDatagramCapsule512WireForTest(t *testing.T, payload []byte) []byte {
	t.Helper()
	var wire bytes.Buffer
	require.NoError(t, h2c.AppendDatagramCapsuleWire(&wire, payload))
	return wire.Bytes()
}

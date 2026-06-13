package connectudp

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
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

func TestParseHTTPDatagramUDPZeroContext(t *testing.T) {
	p, ok, err := ParseHTTPDatagramUDP([]byte{0, 'a', 'b'})
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

// TestH2PacketConnSkipsMalformedHTTPDatagramThenReadsValid verifies that a non-DATAGRAM capsule whose
// value exceeds the DATAGRAM MTU cap is skipped (RFC 9297 allows other capsule types on the stream)
// rather than being mis-parsed as an oversized DATAGRAM payload.
// Regression: malformed HTTP Datagram payload inside a well-formed DATAGRAM capsule must be dropped
// like masque-go proxiedConn.ReadFrom / parseProxiedDatagramPayload (do not Close or fail the relay).
func TestH2PacketConnSkipsMalformedHTTPDatagramThenReadsValid(t *testing.T) {
	var wire bytes.Buffer
	// Truncated 2-byte context varint prefix (0x40 >> 6 == 1) — parse returns (_, false, io.EOF).
	require.NoError(t, http3.WriteCapsule(&wire, http3.CapsuleType(h2c.CapsuleTypeDatagram), []byte{0x40}))
	require.NoError(t, http3.WriteCapsule(&wire, http3.CapsuleType(h2c.CapsuleTypeDatagram), []byte{0, 'z'}))

	c := NewH2PacketConn(H2PacketConnConfig{
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

func TestH2PacketConnReadFromCleanEOFWrapped(t *testing.T) {
	wrapped := fmt.Errorf("upstream: %w", io.EOF)
	c := NewH2PacketConn(H2PacketConnConfig{
		Resp: &http.Response{Body: io.NopCloser(h2UDPReadReturnErr{err: wrapped})},
	})
	_, _, err := c.ReadFrom(make([]byte, 8))
	require.ErrorIs(t, err, io.EOF)
	require.False(t, c.IsClosed())
}

func TestH2PacketConnSkipsLargeNonDatagramCapsule(t *testing.T) {
	var wire bytes.Buffer
	large := make([]byte, h2c.MaxCapsulePayload()+100)
	require.NoError(t, http3.WriteCapsule(&wire, http3.CapsuleType(1), large))
	dgram := []byte{0, 'x'}
	require.NoError(t, http3.WriteCapsule(&wire, http3.CapsuleType(h2c.CapsuleTypeDatagram), dgram))

	c := NewH2PacketConn(H2PacketConnConfig{
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
func TestH2PacketConnClosesOnTruncatedCapsulePrefix(t *testing.T) {
	var hdr bytes.Buffer
	hdr.Write(quicvarint.Append(nil, uint64(http3.CapsuleType(h2c.CapsuleTypeDatagram))))
	// truncated length varint — ParseCapsule parity expects UnexpectedEOF, not silent EOF
	c := NewH2PacketConn(H2PacketConnConfig{
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
func TestH2PacketConnClosesOnWriteBodyError(t *testing.T) {
	pr, pw := io.Pipe()
	_ = pr.CloseWithError(errors.New("test closed read side"))

	c := NewH2PacketConn(H2PacketConnConfig{ReqBody: pw})
	n, err := c.WriteTo([]byte{42}, nil)
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
func TestH2PacketConnWriteToCleanEOFWithoutClose(t *testing.T) {
	c := NewH2PacketConn(H2PacketConnConfig{
		ReqBody: eofWriteCloser{},
	})
	n, err := c.WriteTo([]byte{1, 2, 3}, nil)
	require.Equal(t, 0, n)
	require.ErrorIs(t, err, io.EOF)
	require.False(t, c.IsClosed())
}

type errClosedPipeWriteCloser struct{}

func (errClosedPipeWriteCloser) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (errClosedPipeWriteCloser) Close() error              { return nil }

func TestH2PacketConnWriteToCleanErrClosedPipeWithoutClose(t *testing.T) {
	c := NewH2PacketConn(H2PacketConnConfig{
		ReqBody: errClosedPipeWriteCloser{},
	})
	n, err := c.WriteTo([]byte{1, 2, 3}, nil)
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
func TestH2PacketConnWriteToEmptyEmitCapsule(t *testing.T) {
	cap := &udpCapsuleCaptureWriteCloser{}
	c := NewH2PacketConn(H2PacketConnConfig{ReqBody: cap})

	n, err := c.WriteTo([]byte(nil), nil)
	require.NoError(t, err)
	require.Zero(t, n)
	require.NotEmpty(t, cap.buf.Bytes())

	ct, cr, err := h2c.ParseCapsule(quicvarint.NewReader(bytes.NewReader(cap.buf.Bytes())))
	require.NoError(t, err)
	require.Equal(t, h2c.CapsuleTypeDatagram, ct)
	raw, err := io.ReadAll(cr)
	require.NoError(t, err)
	payload, ok, perr := ParseHTTPDatagramUDP(raw)
	require.NoError(t, perr)
	require.True(t, ok)
	require.Empty(t, payload)
}

// Regression: one WriteTo must not emit a single DATAGRAM capsule whose HTTP Datagram exceeds
// h2c.MaxCapsulePayload() (server uplink rejects; parity with ServeH2 downlink splitter).
func TestH2PacketConnWriteToSplitsLargePayloadIntoRFC9297Capsules(t *testing.T) {
	total := h2c.MaxUDPPayloadPerDatagramCapsule()*2 + 50
	payload := bytes.Repeat([]byte{'q'}, total)
	capWC := &udpCapsuleCaptureWriteCloser{}
	c := NewH2PacketConn(H2PacketConnConfig{ReqBody: capWC})

	n, err := c.WriteTo(payload, nil)
	require.NoError(t, err)
	require.Equal(t, total, n)

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
		pl, ok, perr := ParseHTTPDatagramUDP(raw)
		require.NoError(t, perr)
		require.True(t, ok)
		reassembled = append(reassembled, pl...)
	}
	require.Equal(t, payload, reassembled)
}

func TestH2PacketConnRejectsOversizedNondatagramCapsule(t *testing.T) {
	var wire bytes.Buffer
	big := make([]byte, h2c.NondatagramMaxCapsulePayload+1)
	require.NoError(t, http3.WriteCapsule(&wire, http3.CapsuleType(7), big))

	c := NewH2PacketConn(H2PacketConnConfig{
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
func TestH2PacketConnConcurrentReadFromSerializesReads(t *testing.T) {
	var wire bytes.Buffer
	for _, b := range []byte{'a', 'b'} {
		dgram := []byte{0, b}
		require.NoError(t, http3.WriteCapsule(&wire, http3.CapsuleType(h2c.CapsuleTypeDatagram), dgram))
	}
	c := NewH2PacketConn(H2PacketConnConfig{
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

func TestH2PacketConnReadFromEmptyDatagramICMPRefused(t *testing.T) {
	var wb bytes.Buffer
	if err := h2c.WriteDatagramCapsule(&wb, nil); err != nil {
		t.Fatal(err)
	}
	c := NewH2PacketConn(H2PacketConnConfig{
		Resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(wb.Bytes()))},
		RemoteAddr: NewUDPAddr("192.0.2.3:5201"),
	})
	n, _, err := c.ReadFrom(make([]byte, 64))
	require.Equal(t, 0, n)
	require.ErrorIs(t, err, ErrPortUnreachable)
}

func TestH2PacketConnReadFromDropsShortNonICMPPayload(t *testing.T) {
	var wb bytes.Buffer
	// DATAGRAM capsule: context id 0 + 4-byte slop (< DNS header) then empty ICMP.
	if err := h2c.WriteDatagramCapsule(&wb, []byte{0xde, 0xad, 0xbe, 0xef}); err != nil {
		t.Fatal(err)
	}
	if err := h2c.WriteDatagramCapsule(&wb, nil); err != nil {
		t.Fatal(err)
	}
	c := NewH2PacketConn(H2PacketConnConfig{
		Resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(wb.Bytes()))},
		RemoteAddr: NewUDPAddr("192.0.2.3:5201"),
		AsyncDownlink: true,
	})
	go c.RunDownlinkPump()
	n, _, err := c.ReadFrom(make([]byte, 64))
	require.Equal(t, 0, n)
	require.ErrorIs(t, err, ErrPortUnreachable)
}

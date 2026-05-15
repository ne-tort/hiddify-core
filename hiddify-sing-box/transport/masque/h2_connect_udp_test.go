package masque

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"

	"github.com/sagernet/sing-box/option"
)

// dialTimeoutNetErr is synthetic net-compatible timeout text matching common Windows dial failures
// that omit legacy "i/o timeout" tokens.
type dialTimeoutNetErr struct{}

func (dialTimeoutNetErr) Error() string {
	return `dial tcp 198.51.100.1:443: connectex: A connection attempt failed because the connected party did not properly respond after a period of time`
}

func (dialTimeoutNetErr) Timeout() bool   { return true }
func (dialTimeoutNetErr) Temporary() bool { return false }

// chunkWriter simulates an io.Writer that may return n < len(p) without error (allowed by contract).
type chunkWriter struct {
	max int
	buf bytes.Buffer
}

func (c *chunkWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := len(p)
	if n > c.max {
		n = c.max
	}
	return c.buf.Write(p[:n])
}

func TestWriteAllIOWriterCompletesPartialWrites(t *testing.T) {
	w := &chunkWriter{max: 7}
	payload := bytes.Repeat([]byte{'z'}, 100)
	n, err := writeAllIOWriter(w, payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	require.Equal(t, payload, w.buf.Bytes())
}

// partialFailWriter returns a short write together with an error on the first call (allowed by io.Writer).
// Callers like writeAllIOWriter must observe n>0 on that path; h2UDPUploadWriter must not collapse n to 0.
type partialFailWriter struct {
	calls int
}

func (w *partialFailWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == 1 {
		if len(p) < 2 {
			return len(p), errors.New("test short write")
		}
		return 2, errors.New("test short write")
	}
	return len(p), nil
}

func (*partialFailWriter) Close() error { return nil }

func TestH2UDPUploadWriterPropagatesPartialWriteOnError(t *testing.T) {
	uw := &h2UDPUploadWriter{c: &h2ConnectUDPPacketConn{reqBody: &partialFailWriter{}}}
	n, err := uw.Write([]byte("hello"))
	require.Error(t, err)
	require.Equal(t, 2, n, "io.Writer must return bytes written before error (writeAllIOWriter / net/http rely on this)")
}

func TestEnsureH2UDPTransportSetsDisableCompression(t *testing.T) {
	ctx := context.Background()
	s := &coreSession{
		options: ClientOptions{
			Server: "example.com",
			TCPDial: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("dial not used in this test")
			},
		},
	}
	tr, err := s.ensureH2UDPTransport(ctx)
	require.NoError(t, err)
	require.True(t, tr.DisableCompression, "H2 MASQUE dataplane must not negotiate gzip (breaks CONNECT stream framing)")
	tr2, err := s.ensureH2UDPTransport(ctx)
	require.NoError(t, err)
	require.Same(t, tr, tr2)
	require.True(t, tr2.DisableCompression)
}

func TestWarpMasqueH2AlternateDialHostSwapsSiblingIPv4(t *testing.T) {
	require.Equal(t, "162.159.198.2", warpMasqueH2AlternateDialHost("162.159.198.1"))
	require.Equal(t, "162.159.198.1", warpMasqueH2AlternateDialHost("162.159.198.2"))
}

func TestWarpMasqueH2AlternateDialHostRejectsNonSiblingIPv4(t *testing.T) {
	require.Equal(t, "", warpMasqueH2AlternateDialHost("162.159.198.3"))
	require.Equal(t, "", warpMasqueH2AlternateDialHost("engage.cloudflareclient.com"))
	require.Equal(t, "", warpMasqueH2AlternateDialHost("2606:4700::1111"))
}

func TestH2DialHostCandidatesCfConnectIPForcesAlternateOnly(t *testing.T) {
	got := h2DialHostCandidates("cf-connect-ip", "162.159.198.1", "162.159.198.2")
	require.Equal(t, []string{"162.159.198.2"}, got)
}

func TestH2DialHostCandidatesNonCfKeepsPrimaryThenAlternate(t *testing.T) {
	got := h2DialHostCandidates("connect-ip", "162.159.198.1", "162.159.198.2")
	require.Equal(t, []string{"162.159.198.1", "162.159.198.2"}, got)
}

func TestParseMasqueHTTPDatagramUDPZeroContext(t *testing.T) {
	p, ok, err := ParseMasqueHTTPDatagramUDP([]byte{0, 'a', 'b'})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, []byte("ab"), p)
}

func TestWriteMasqueCapsuleUDPFrame(t *testing.T) {
	var buf bytes.Buffer
	dgram := []byte{0, 'z'}
	require.NoError(t, http3.WriteCapsule(&buf, capsuleTypeDatagram, dgram))
	require.Greater(t, buf.Len(), 3)
}

// Regression: bogus declared capsule length must be rejected without draining the advertised span into Discard
// (http3.ParseCapsule + io.Copy(io.Discard, reader) admitted hostiles before this hard cap).
func TestParseH2ConnectUDPCapsuleRejectsAstronomicDatagramDeclaredLength(t *testing.T) {
	var hdr bytes.Buffer
	hdr.Write(quicvarint.Append(nil, uint64(capsuleTypeDatagram)))
	hdr.Write(quicvarint.Append(nil, uint64(h2ConnectUDPMaxCapsulePayload)+1_000_000))
	vr := quicvarint.NewReader(bytes.NewReader(hdr.Bytes()))
	_, _, err := parseH2ConnectUDPCapsule(vr)
	require.Error(t, err)
	require.ErrorIs(t, err, errMasqueH2ConnectUDPOversizedDeclared)
	require.Contains(t, err.Error(), "DATAGRAM capsule payload exceeds")
}

// TestH2ConnectUDPPacketConnSkipsLargeNonDatagramCapsule verifies that a non-DATAGRAM capsule whose
// value exceeds the DATAGRAM MTU cap is skipped (RFC 9297 allows other capsule types on the stream)
// rather than being mis-parsed as an oversized DATAGRAM payload.
// Regression: malformed HTTP Datagram payload inside a well-formed DATAGRAM capsule must be dropped
// like masque-go proxiedConn.ReadFrom / parseProxiedDatagramPayload (do not Close or fail the relay).
func TestH2ConnectUDPPacketConnSkipsMalformedHTTPDatagramThenReadsValid(t *testing.T) {
	var wire bytes.Buffer
	// Truncated 2-byte context varint prefix (0x40 >> 6 == 1) — parse returns (_, false, io.EOF).
	require.NoError(t, http3.WriteCapsule(&wire, capsuleTypeDatagram, []byte{0x40}))
	require.NoError(t, http3.WriteCapsule(&wire, capsuleTypeDatagram, []byte{0, 'z'}))

	c := &h2ConnectUDPPacketConn{
		resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(wire.Bytes()))},
		remoteAddr: masqueUDPAddr{s: "127.0.0.1:1"},
	}
	buf := make([]byte, 64)
	n, _, err := c.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, byte('z'), buf[0])
	require.False(t, c.closed.Load())
}

// Regression: io.EOF must be detected with errors.Is so a wrapped clean shutdown does not look like
// capsule mis-framing (which closes the tunnel via ReadFrom).
type h2UDPReadReturnErr struct{ err error }

func (r h2UDPReadReturnErr) Read(p []byte) (int, error) { return 0, r.err }

func TestH2ConnectUDPPacketConnReadFromCleanEOFWrapped(t *testing.T) {
	wrapped := fmt.Errorf("upstream: %w", io.EOF)
	c := &h2ConnectUDPPacketConn{
		resp: &http.Response{Body: io.NopCloser(h2UDPReadReturnErr{err: wrapped})},
	}
	_, _, err := c.ReadFrom(make([]byte, 8))
	require.ErrorIs(t, err, io.EOF)
	require.False(t, c.closed.Load())
}

func TestH2ConnectUDPPacketConnSkipsLargeNonDatagramCapsule(t *testing.T) {
	var wire bytes.Buffer
	large := make([]byte, h2ConnectUDPMaxCapsulePayload+100)
	require.NoError(t, http3.WriteCapsule(&wire, http3.CapsuleType(1), large))
	dgram := []byte{0, 'x'}
	require.NoError(t, http3.WriteCapsule(&wire, capsuleTypeDatagram, dgram))

	c := &h2ConnectUDPPacketConn{
		resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(wire.Bytes()))},
		remoteAddr: masqueUDPAddr{s: "127.0.0.1:1"},
	}
	buf := make([]byte, 64)
	n, _, err := c.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, byte('x'), buf[0])
}

// Regression: corrupt capsule framing after CONNECT-UDP closes the tunnel (stream stays misaligned).
func TestH2ConnectUDPPacketConnClosesOnTruncatedCapsulePrefix(t *testing.T) {
	var hdr bytes.Buffer
	hdr.Write(quicvarint.Append(nil, uint64(capsuleTypeDatagram)))
	// truncated length varint — ParseCapsule parity expects UnexpectedEOF, not silent EOF
	c := &h2ConnectUDPPacketConn{
		resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(hdr.Bytes()))},
		remoteAddr: masqueUDPAddr{s: "127.0.0.1:1"},
	}
	buf := make([]byte, 64)
	n, _, err := c.ReadFrom(buf)
	if err == nil {
		t.Fatal("expected error")
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes read, got %d", n)
	}
	if !c.closed.Load() {
		t.Fatal("expected PacketConn closed after capsule parse failure")
	}
}

// Regression: failed upload after CONNECT must close the PacketConn like read-side capsule faults.
func TestH2ConnectUDPPacketConnClosesOnWriteBodyError(t *testing.T) {
	pr, pw := io.Pipe()
	_ = pr.CloseWithError(errors.New("test closed read side"))

	c := &h2ConnectUDPPacketConn{reqBody: pw}
	n, err := c.WriteTo([]byte{42}, nil)
	require.Error(t, err)
	require.Equal(t, 0, n)
	require.Contains(t, err.Error(), "write body")
	require.True(t, c.closed.Load())
}

type eofWriteCloser struct{}

func (eofWriteCloser) Write([]byte) (int, error) { return 0, io.EOF }
func (eofWriteCloser) Close() error              { return nil }

// Plain io.EOF on request-body write mirrors ReadFrom when the CONNECT response body ends: no Close(),
// no dataplane wrapper (http_layer_fallback / classifiers stay off normal half-close semantics).
func TestH2ConnectUDPPacketConnWriteToCleanEOFWithoutClose(t *testing.T) {
	c := &h2ConnectUDPPacketConn{
		reqBody: eofWriteCloser{},
	}
	n, err := c.WriteTo([]byte{1, 2, 3}, nil)
	require.Equal(t, 0, n)
	require.ErrorIs(t, err, io.EOF)
	require.False(t, c.closed.Load())
}

type errClosedPipeWriteCloser struct{}

func (errClosedPipeWriteCloser) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (errClosedPipeWriteCloser) Close() error              { return nil }

func TestH2ConnectUDPPacketConnWriteToCleanErrClosedPipeWithoutClose(t *testing.T) {
	c := &h2ConnectUDPPacketConn{
		reqBody: errClosedPipeWriteCloser{},
	}
	n, err := c.WriteTo([]byte{1, 2, 3}, nil)
	require.Equal(t, 0, n)
	require.ErrorIs(t, err, io.ErrClosedPipe)
	require.False(t, c.closed.Load())
}

type udpCapsuleCaptureWriteCloser struct{ buf bytes.Buffer }

func (c *udpCapsuleCaptureWriteCloser) Write(p []byte) (int, error) {
	return c.buf.Write(p)
}

func (c *udpCapsuleCaptureWriteCloser) Close() error { return nil }

// Parity with third_party masque-go proxiedConn WriteTo(minCap=1 on empty payloads): CONNECT-UDP H2 must
// serialize a DATAGRAM capsule for zero-length UDP, not silently drop egress.
func TestH2ConnectUDPPacketConnWriteToEmptyEmitCapsule(t *testing.T) {
	cap := &udpCapsuleCaptureWriteCloser{}
	c := &h2ConnectUDPPacketConn{reqBody: cap}

	n, err := c.WriteTo([]byte(nil), nil)
	require.NoError(t, err)
	require.Zero(t, n)
	require.NotEmpty(t, cap.buf.Bytes())

	ct, cr, err := parseH2ConnectUDPCapsule(quicvarint.NewReader(bytes.NewReader(cap.buf.Bytes())))
	require.NoError(t, err)
	require.Equal(t, capsuleTypeDatagram, ct)
	raw, err := io.ReadAll(cr)
	require.NoError(t, err)
	payload, ok, perr := ParseMasqueHTTPDatagramUDP(raw)
	require.NoError(t, perr)
	require.True(t, ok)
	require.Empty(t, payload)
}

// Regression: one WriteTo must not emit a single DATAGRAM capsule whose HTTP Datagram exceeds
// h2ConnectUDPMaxCapsulePayload (server uplink rejects; parity with ServeH2ConnectUDP downlink splitter).
func TestH2ConnectUDPPacketConnWriteToSplitsLargePayloadIntoRFC9297Capsules(t *testing.T) {
	total := h2ConnectUDPMaxUDPPayloadPerDatagramCapsule*2 + 50
	payload := bytes.Repeat([]byte{'q'}, total)
	capWC := &udpCapsuleCaptureWriteCloser{}
	c := &h2ConnectUDPPacketConn{reqBody: capWC}

	n, err := c.WriteTo(payload, nil)
	require.NoError(t, err)
	require.Equal(t, total, n)

	r := quicvarint.NewReader(bytes.NewReader(capWC.buf.Bytes()))
	var reassembled []byte
	for {
		ct, cr, cerr := parseH2ConnectUDPCapsule(r)
		if cerr != nil {
			if cerr == io.EOF {
				break
			}
			require.NoError(t, cerr)
		}
		require.Equal(t, capsuleTypeDatagram, ct)
		raw, rerr := io.ReadAll(cr)
		require.NoError(t, rerr)
		pl, ok, perr := ParseMasqueHTTPDatagramUDP(raw)
		require.NoError(t, perr)
		require.True(t, ok)
		reassembled = append(reassembled, pl...)
	}
	require.Equal(t, payload, reassembled)
}

func TestH2ConnectUDPPacketConnRejectsOversizedNondatagramCapsule(t *testing.T) {
	var wire bytes.Buffer
	big := make([]byte, h2ConnectUDPNondatagramMaxCapsulePayload+1)
	require.NoError(t, http3.WriteCapsule(&wire, http3.CapsuleType(7), big))

	c := &h2ConnectUDPPacketConn{
		resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(wire.Bytes()))},
		remoteAddr: masqueUDPAddr{s: "127.0.0.1:1"},
	}
	buf := make([]byte, 64)
	n, _, err := c.ReadFrom(buf)
	require.Error(t, err)
	require.Equal(t, 0, n)
	require.Contains(t, err.Error(), "non-datagram capsule exceeds")
	require.True(t, c.closed.Load())
}

// net.PacketConn allows concurrent method calls; serialized ReadFrom avoids concurrent reads on the shared response body reader.
func TestH2ConnectUDPPacketConnConcurrentReadFromSerializesReads(t *testing.T) {
	var wire bytes.Buffer
	for _, b := range []byte{'a', 'b'} {
		dgram := []byte{0, b}
		require.NoError(t, http3.WriteCapsule(&wire, capsuleTypeDatagram, dgram))
	}
	c := &h2ConnectUDPPacketConn{
		resp:       &http.Response{Body: io.NopCloser(bytes.NewReader(wire.Bytes()))},
		remoteAddr: masqueUDPAddr{s: "192.0.2.1:53"},
	}
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

func TestIsMasqueHTTPLayerSwitchableFailure(t *testing.T) {
	if !IsMasqueHTTPLayerSwitchableFailure(errors.New("Extended CONNECT xyz")) {
		t.Fatal("expected switchable")
	}
	if !IsMasqueHTTPLayerSwitchableFailure(errors.New(`http2: server sent GOAWAY and closed the connection`)) {
		t.Fatal("expected GOAWAY to be switchable for h2 fallback")
	}
	if !IsMasqueHTTPLayerSwitchableFailure(errors.New(`stream error: stream ID 3; RST_STREAM`)) {
		t.Fatal("expected RST_STREAM/stream error switchable")
	}
	if !IsMasqueHTTPLayerSwitchableFailure(errors.New("write tcp: broken pipe")) {
		t.Fatal("expected broken pipe switchable")
	}
	if !IsMasqueHTTPLayerSwitchableFailure(errors.New("read tcp 198.51.100.1:443->198.51.100.2:45678: read: connection timed out")) {
		t.Fatal("expected connection timed out switchable (Linux-style errno text)")
	}
	// Windows-style connectex message often has no "i/o timeout" / "connection timed out" substring;
	// classify via net.Error.Timeout(), not substring-only heuristics.
	if !IsMasqueHTTPLayerSwitchableFailure(dialTimeoutNetErr{}) {
		t.Fatal("expected net.Error.Timeout() dial without legacy tokens to be switchable")
	}
	if IsMasqueHTTPLayerSwitchableFailure(&net.DNSError{Name: "slow.example.invalid", Server: "9.9.9.9:53", IsTimeout: true}) {
		t.Fatal("DNS timeout must not consume http_layer_fallback (same resolver for both overlays)")
	}
	if IsMasqueHTTPLayerSwitchableFailure(fmt.Errorf("wrap: %w", &net.DNSError{Name: "x", IsTimeout: true})) {
		t.Fatal("wrapped DNS timeout must not flip HTTP layer")
	}
	if !IsMasqueHTTPLayerSwitchableFailure(errors.New("wsarecv: An existing connection was forcibly closed by the remote host.")) {
		t.Fatal("expected forcibly-closed TCP switchable (Windows-style)")
	}
	if !IsMasqueHTTPLayerSwitchableFailure(errors.New("read tcp: use of closed network connection")) {
		t.Fatal("expected stdlib closed-conn switchable")
	}
	if IsMasqueHTTPLayerSwitchableFailure(ErrConnectIPTemplateNotConfigured) {
		t.Fatal("missing CONNECT-IP template sentinel must not flip HTTP layer")
	}
	if IsMasqueHTTPLayerSwitchableFailure(fmt.Errorf("parse: %w", errMasqueH2ConnectUDPOversizedDeclared)) {
		t.Fatal("H2 CONNECT-UDP declared-length capsule rejection must not flip HTTP layer")
	}
	if IsMasqueHTTPLayerSwitchableFailure(fmt.Errorf("masque connect-ip h2: %w", ErrConnectIPTemplateNotConfigured)) {
		t.Fatal("wrapped template sentinel must not flip despite masque connect-ip h2 substring")
	}
	if IsMasqueHTTPLayerSwitchableFailure(net.ErrClosed) {
		t.Fatal("net.ErrClosed sentinel (incl. bare from CONNECT-IP H2 capsule path) must not flip HTTP layer")
	}
	if IsMasqueHTTPLayerSwitchableFailure(fmt.Errorf("recv: %w", net.ErrClosed)) {
		t.Fatal("wrapped net.ErrClosed must not flip HTTP layer")
	}
	if IsMasqueHTTPLayerSwitchableFailure(&connectip.CloseError{Remote: true}) {
		t.Fatal("CONNECT-IP CloseError must not flip HTTP layer despite net.ErrClosed-compatible Error() text")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.Join(errors.New("read packet"), &connectip.CloseError{Remote: false})) {
		t.Fatal("wrapped CONNECT-IP CloseError must not flip HTTP layer")
	}
	if !IsMasqueHTTPLayerSwitchableFailure(errors.New("write tcp: The pipe is being closed.")) {
		t.Fatal("expected Windows pipe-closed switchable")
	}
	if !IsMasqueHTTPLayerSwitchableFailure(errors.New("masque connect-ip h2: roundtrip refused")) {
		t.Fatal("expected CONNECT-IP/H2 handshake prefix switchable")
	}
	if !IsMasqueHTTPLayerSwitchableFailure(errors.New("masque h2: tcp dialer is not configured")) {
		t.Fatal("expected H2-only setup error to be switchable so auto/fallback can try H3 overlay")
	}
	if !IsMasqueHTTPLayerSwitchableFailure(errors.New("masque h2: tcp connect-stream roundtrip: reset by peer")) {
		t.Fatal("expected H2 CONNECT-stream errors with canonical masque h2 prefix to be switchable")
	}
	// dialTCPStreamHTTP3 non-Auth HTTP failure: parity with dialTCPStreamH2 (masque h2: prefix).
	if !IsMasqueHTTPLayerSwitchableFailure(fmt.Errorf("%w: status=%d url=%s",
		ErrTCPConnectStreamFailed, http.StatusBadGateway, "https://example.invalid/connect")) {
		t.Fatal("expected H3 CONNECT-stream non-2xx ErrTCPConnectStreamFailed shape to be switchable")
	}
	if !IsMasqueHTTPLayerSwitchableFailure(fmt.Errorf("masque h2: %w: status=%d url=%s",
		ErrTCPConnectStreamFailed, http.StatusBadGateway, "https://example.invalid/connect")) {
		t.Fatal("expected H2 CONNECT-stream non-2xx (aligned ErrTCP shape) to be switchable")
	}
	// H3 CONNECT-UDP / CONNECT-IP handshake HTTP status from third_party libraries (no masque h2: wrapper).
	if !IsMasqueHTTPLayerSwitchableFailure(errors.New("masque: server responded with 502")) {
		t.Fatal("expected masque-go CONNECT-UDP non-2xx to be switchable for H3→H2 fallback")
	}
	if !IsMasqueHTTPLayerSwitchableFailure(errors.New("connect-ip: server responded with 502")) {
		t.Fatal("expected connect-ip-go H3 CONNECT-IP non-2xx to be switchable for H3→H2 fallback")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.New("masque: server responded with 401")) {
		t.Fatal("CONNECT-UDP auth status must not flip layer")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.New("connect-ip: server responded with 403")) {
		t.Fatal("CONNECT-IP auth status must not flip layer")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.New("connect-ip: server responded with 407")) {
		t.Fatal("CONNECT-IP 407 must not flip layer")
	}
	if !IsMasqueHTTPLayerSwitchableFailure(errors.New("dial udp 198.51.100.1:1401: connection refused")) {
		t.Fatal("dial failures on port 1401 must not be confused with HTTP 401 substring match")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.New("connect-ip: malformed datagram: too short")) {
		t.Fatal("library dataplane errors must not trigger HTTP layer flip")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.New("masque h2 dataplane connect-udp capsule: corrupt framing")) {
		t.Fatal("post-handshake H2 CONNECT-UDP dataplane errors must not trigger HTTP layer flip")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.New("masque h2 dataplane: extended connect capsule parse failed")) {
		t.Fatal("dataplane errors must not flip layer even if they mention extended connect")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.New("masque connect-ip h2 dataplane: connect-ip: truncated capsule (extended connect noise in nested cause)")) {
		t.Fatal("CONNECT-IP H2 stream dataplane must not flip layer when nested text looks like handshake")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.New("masque connect-ip h2 dataplane: write tcp: broken pipe")) {
		t.Fatal("CONNECT-IP H2 dataplane send/write must not consume http_layer_fallback")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.New("masque connect-ip h2 dataplane: connect-ip: compose datagram: policy: extended connect noise")) {
		t.Fatal("H2 CONNECT-IP compose failures must not flip layer when nested text resembles handshake tokens")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.New("masque connect-ip h3 dataplane: connect-ip: tls handshake while sending QUIC datagram")) {
		t.Fatal("CONNECT-IP H3 QUIC dataplane must not flip layer when nested text looks like handshake")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.New("masque h2 dataplane connect-udp server capsule: unexpected EOF")) {
		t.Fatal("server-side H2 CONNECT-UDP relay dataplane must not flip HTTP layer")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.New("masque h2 dataplane connect-udp server non-datagram capsule exceeds 65536 bytes")) {
		t.Fatal("oversized non-datagram capsules must stay dataplane classification")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.New(`masque h2 dataplane connect-stream write: stream error`)) {
		t.Fatal("H2 CONNECT-stream dataplane faults must not flip HTTP layer")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.New(`masque h3 dataplane connect-stream read: QUIC transport: pseudo handshake expired`)) {
		t.Fatal("H3 CONNECT-stream dataplane faults must not flip HTTP layer when nested text looks like handshake")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.New("masque h3 dataplane connect-udp read: transport: QUIC extended connect noise")) {
		t.Fatal("H3 CONNECT-UDP dataplane faults must not flip HTTP layer when nested text looks like handshake")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.New("masque h3 dataplane connect-udp write: tls handshake while sending datagram")) {
		t.Fatal("H3 CONNECT-UDP dataplane write must not flip HTTP layer on nested handshake-like text")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.New("masque connect-udp h3 skip-capsules: type=7 capsule exceeds 65536 bytes")) {
		t.Fatal("H3 skip-capsules drain policy errors must not consume http_layer_fallback")
	}
	if IsMasqueHTTPLayerSwitchableFailure(errors.New("401 Unauthorized")) {
		t.Fatal("auth must not flip layer")
	}
	if IsMasqueHTTPLayerSwitchableFailure(nil) {
		t.Fatal("nil err")
	}
}

// startInProcessH2UDPConnectProxy serves HTTPS + HTTP/2 with RFC 8441 CONNECT-UDP and relays UDP via ServeH2ConnectUDP.
func startInProcessH2UDPConnectProxy(t *testing.T) int {
	t.Helper()
	serverTLS := connectUDPTestTLS.Clone()
	serverTLS.NextProtos = []string{http2.NextProtoTLS, "http/1.1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/masque/udp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if strings.TrimSpace(r.Header.Get(":protocol")) != h2ConnectUDPProto {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		host := r.PathValue("target_host")
		port := r.PathValue("target_port")
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValueH2())
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_ = ServeH2ConnectUDP(w, r, conn)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	tlsLn := tls.NewListener(ln, serverTLS)
	srv := &http.Server{
		Handler: mux,
	}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		t.Fatalf("configure http2 server: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = srv.Serve(tlsLn)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		wg.Wait()
	})
	time.Sleep(20 * time.Millisecond)
	return tlsLn.Addr().(*net.TCPAddr).Port
}

func TestH2ConnectUDPEchoRoundTripInProcess(t *testing.T) {
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	proxyPort := startInProcessH2UDPConnectProxy(t)

	rawTpl := "https://127.0.0.1:" + strconv.Itoa(proxyPort) + "/masque/udp/{target_host}/{target_port}"
	tpl, err := uritemplate.New(rawTpl)
	require.NoError(t, err)

	s := &coreSession{
		options: ClientOptions{
			Server:              "127.0.0.1",
			ServerPort:          uint16(proxyPort),
			MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		},
	}
	s.options.TCPDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	s.udpHTTPLayer.Store(option.MasqueHTTPLayerH2)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	pc, err := s.dialUDPOverHTTP2(ctx, tpl, net.JoinHostPort("127.0.0.1", strconv.Itoa(echoPort)))
	require.NoError(t, err)
	defer pc.Close()

	payload := []byte("ping-h2-udp-echo")
	nw, err := pc.WriteTo(payload, nil)
	require.NoError(t, err)
	require.Equal(t, len(payload), nw)

	buf := make([]byte, 256)
	nr, _, err := pc.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, payload, buf[:nr])
}

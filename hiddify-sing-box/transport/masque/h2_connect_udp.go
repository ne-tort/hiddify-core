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
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dunglas/httpsfv"
	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

const (
	capsuleTypeDatagram http3.CapsuleType = 0x00
	h2ConnectUDPProto                     = "connect-udp"
	// CONNECT-UDP URI template variables (masque-go parity).
	uriTemplateTargetHostKey = "target_host"
	uriTemplateTargetPortKey = "target_port"
	// h2ConnectUDPMaxCapsulePayload bounds DATAGRAM capsule declared length on the wire (parity with
	// ServeH2ConnectUDP). Hostile varints must be rejected in parseH2ConnectUDPCapsule before body I/O.
	h2ConnectUDPMaxCapsulePayload = 1500 + 128
	// h2ConnectUDPMaxUDPPayloadPerDatagramCapsule is the largest UDP payload per RFC 9297 DATAGRAM
	// capsule: WriteCapsule body is 1-byte context id + udp bytes and must satisfy
	// h2ConnectUDPMaxCapsulePayload.
	h2ConnectUDPMaxUDPPayloadPerDatagramCapsule = h2ConnectUDPMaxCapsulePayload - 1
	// h2ConnectUDPNondatagramMaxCapsulePayload caps declared length for non-DATAGRAM RFC 9297 capsules;
	// parse rejects larger values before LimitedReader construction (no unbounded drain).
	h2ConnectUDPNondatagramMaxCapsulePayload = 65536
	// h2ConnectUDPServerUDPReadBuf is the server relay UDP recv buffer: must hold a full kernel
	// datagram; net.UDPConn.Read truncates without error when the buffer is smaller than the packet.
	h2ConnectUDPServerUDPReadBuf = 65535
)

// errMasqueH2ConnectUDPOversizedDeclared tags rejections of hostile capsule length varints before any
// body I/O so ReadFrom can close the QUIC/H2 tunnel and avoids io.Copy(io.Discard, …) over the full declared span.
var errMasqueH2ConnectUDPOversizedDeclared = errors.New("masque h2 connect-udp oversized capsule declaration")

// writeAllIOWriter writes all of p to w per the io.Writer contract (partial writes without error).
// Parity with masqueUDPDatagramSplitConn: a single short Write must not start the next capsule on the wire.
func writeAllIOWriter(w io.Writer, p []byte) (int, error) {
	if w == nil {
		return 0, errors.New("nil writer")
	}
	nn := 0
	for nn < len(p) {
		n, err := w.Write(p[nn:])
		nn += n
		if err != nil {
			return nn, err
		}
		if n == 0 {
			return nn, io.ErrShortWrite
		}
	}
	return nn, nil
}

func writeUDPH2ConnectDatagramCapsule(w io.Writer, flusher http.Flusher, udpPayload []byte) error {
	// QUIC/H3 CONNECT-UDP path (proxiedConn.WriteTo / SendDatagram) sends a length-1 QUIC datagram when
	// the UDP payload is empty (RFC 9297 payload is still one context-id byte); keep parity for H2 relays.
	dgram := make([]byte, 1+len(udpPayload))
	dgram[0] = 0
	copy(dgram[1:], udpPayload)
	var buf bytes.Buffer
	if err := http3.WriteCapsule(&buf, capsuleTypeDatagram, dgram); err != nil {
		return err
	}
	if _, err := writeAllIOWriter(w, buf.Bytes()); err != nil {
		return err
	}
	if flusher != nil {
		flusher.Flush()
	}
	return nil
}

// writeUDPPayloadAsH2DatagramCapsules sends one UDP payload (possibly larger than one RFC 9297
// DATAGRAM capsule allows) as a sequence of capsules, preserving all bytes — parity with the
// client-side masqueUDPDatagramSplitConn chunk size and ServeH2ConnectUDP downlink framing.
func writeUDPPayloadAsH2DatagramCapsules(w io.Writer, flusher http.Flusher, udpPayload []byte) error {
	if len(udpPayload) == 0 {
		return writeUDPH2ConnectDatagramCapsule(w, flusher, nil)
	}
	step := h2ConnectUDPMaxUDPPayloadPerDatagramCapsule
	for offset := 0; offset < len(udpPayload); {
		end := offset + step
		if end > len(udpPayload) {
			end = len(udpPayload)
		}
		if err := writeUDPH2ConnectDatagramCapsule(w, flusher, udpPayload[offset:end]); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

type h2CapsuleExactReader struct {
	R io.LimitedReader
}

func (r *h2CapsuleExactReader) Read(b []byte) (int, error) {
	n, err := r.R.Read(b)
	if err == io.EOF && r.R.N > 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

// h2countingVarintReader matches http3.countingByteReader for the capsule type prefix (truncated-varint parity).
type h2countingVarintReader struct {
	wrapped quicvarint.Reader
	num     int
}

func (w *h2countingVarintReader) ReadByte() (byte, error) {
	b, err := w.wrapped.ReadByte()
	if err == nil {
		w.num++
	}
	return b, err
}

func (w *h2countingVarintReader) Read(p []byte) (int, error) {
	n, err := w.wrapped.Read(p)
	w.num += n
	return n, err
}

// parseH2ConnectUDPCapsule is like http3.ParseCapsule plus a declared-length cap before body reads,
// mirroring parseConnectIPStreamCapsule in connect-ip-go (parity: skipCapsules / H2 CONNECT-UDP policy).
func parseH2ConnectUDPCapsule(r quicvarint.Reader) (http3.CapsuleType, io.Reader, error) {
	cr := &h2countingVarintReader{wrapped: r}
	ctUint, err := quicvarint.Read(cr)
	if err != nil {
		if err == io.EOF && cr.num > 0 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	length, err := quicvarint.Read(cr)
	if err != nil {
		if err == io.EOF && cr.num > 0 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	ct := http3.CapsuleType(ctUint)
	if ct == capsuleTypeDatagram {
		if length > uint64(h2ConnectUDPMaxCapsulePayload) {
			return 0, nil, fmt.Errorf("%w: DATAGRAM capsule payload exceeds %d bytes",
				errMasqueH2ConnectUDPOversizedDeclared, h2ConnectUDPMaxCapsulePayload)
		}
	} else if length > uint64(h2ConnectUDPNondatagramMaxCapsulePayload) {
		return 0, nil, fmt.Errorf("%w: non-datagram capsule exceeds %d bytes",
			errMasqueH2ConnectUDPOversizedDeclared, h2ConnectUDPNondatagramMaxCapsulePayload)
	}
	return ct, &h2CapsuleExactReader{R: io.LimitedReader{R: r, N: int64(length)}}, nil
}

var capsuleProtoHeaderValueH2 = func() string {
	v, err := httpsfv.Marshal(httpsfv.NewItem(true))
	if err != nil {
		return "?1"
	}
	return v
}()

// CapsuleProtocolHeaderValueH2 returns the Capsule-Protocol structured field for Extended CONNECT over HTTP/2.
func CapsuleProtocolHeaderValueH2() string {
	return capsuleProtoHeaderValueH2
}

func masqueClientH2TLSConfig(opts ClientOptions) *tls.Config {
	base := masqueClientTLSConfig(opts)
	if base == nil {
		return &tls.Config{
			NextProtos: []string{http2.NextProtoTLS},
			ServerName: resolveTLSServerName(opts),
		}
	}
	cfg := base.Clone()
	cfg.NextProtos = []string{http2.NextProtoTLS}
	return cfg
}

type h2ConnectUDPPacketConn struct {
	reqPipeR *io.PipeReader
	reqBody  io.WriteCloser
	resp     *http.Response

	// Mutex for ReadFrom: response body is not safe for concurrent reads; parity with connectIPUDPPacketConn.readMu.
	readMu    sync.Mutex
	writeMu   sync.Mutex
	deadlines connDeadlines
	closed    atomic.Bool

	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *h2ConnectUDPPacketConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *h2ConnectUDPPacketConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *h2ConnectUDPPacketConn) SetDeadline(t time.Time) error {
	c.deadlines.setDeadline(t)
	return nil
}

func (c *h2ConnectUDPPacketConn) SetReadDeadline(t time.Time) error {
	c.deadlines.setReadDeadline(t)
	return nil
}

func (c *h2ConnectUDPPacketConn) SetWriteDeadline(t time.Time) error {
	c.deadlines.setWriteDeadline(t)
	return nil
}

func (c *h2ConnectUDPPacketConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	if c.reqBody != nil {
		_ = c.reqBody.Close()
	}
	if c.reqPipeR != nil {
		_ = c.reqPipeR.Close()
		c.reqPipeR = nil
	}
	if c.resp != nil && c.resp.Body != nil {
		_ = c.resp.Body.Close()
	}
	return nil
}

// h2UDPResponseCapsuleResult is the asynchronous result of framing one RFC 9297 capsule header on the CONNECT-UDP HTTP/2 response body.
type h2UDPResponseCapsuleResult struct {
	ct  http3.CapsuleType
	r   io.Reader
	err error
}

func (c *h2ConnectUDPPacketConn) awaitParseH2UDPResponseCapsule(ctx context.Context) (http3.CapsuleType, io.Reader, error) {
	if c.resp == nil || c.resp.Body == nil {
		return 0, nil, fmt.Errorf("masque h2 dataplane connect-udp: missing HTTP response body")
	}
	body := c.resp.Body
	ch := make(chan h2UDPResponseCapsuleResult, 1)
	go func() {
		ct, cr, cerr := parseH2ConnectUDPCapsule(quicvarint.NewReader(body))
		ch <- h2UDPResponseCapsuleResult{ct: ct, r: cr, err: cerr}
	}()
	select {
	case <-ctx.Done():
		_ = c.Close()
		got := <-ch
		_ = got
		if ce := context.Cause(ctx); errors.Is(ce, context.Canceled) {
			return 0, nil, ce
		}
		return 0, nil, os.ErrDeadlineExceeded
	case got := <-ch:
		return got.ct, got.r, got.err
	}
}

func (c *h2ConnectUDPPacketConn) awaitReadLimitedCapsulePayload(ctx context.Context, r io.Reader) ([]byte, error) {
	ch := make(chan struct {
		b   []byte
		err error
	}, 1)
	go func() {
		b, rerr := io.ReadAll(r)
		ch <- struct {
			b   []byte
			err error
		}{b, rerr}
	}()
	select {
	case <-ctx.Done():
		_ = c.Close()
		got := <-ch
		_ = got
		if ce := context.Cause(ctx); errors.Is(ce, context.Canceled) {
			return nil, ce
		}
		return nil, os.ErrDeadlineExceeded
	case got := <-ch:
		return got.b, got.err
	}
}

func (c *h2ConnectUDPPacketConn) awaitDrainNonDatagramCapsule(ctx context.Context, r io.Reader) error {
	ch := make(chan error, 1)
	go func() {
		_, cerr := io.Copy(io.Discard, r)
		ch <- cerr
	}()
	select {
	case <-ctx.Done():
		_ = c.Close()
		got := <-ch
		_ = got
		if ce := context.Cause(ctx); errors.Is(ce, context.Canceled) {
			return ce
		}
		return os.ErrDeadlineExceeded
	case got := <-ch:
		return got
	}
}

// awaitH2UDPReqBodyWrite runs CONNECT-UDP upload Write in a goroutine so a write deadline can Close the
// tunnel and unblock the pipe (parity with awaitReadLimitedCapsulePayload / connectIPUDPPacketConn).
func (c *h2ConnectUDPPacketConn) awaitH2UDPReqBodyWrite(ctx context.Context, data []byte) (int, error) {
	if c.reqBody == nil {
		return 0, fmt.Errorf("masque h2 dataplane connect-udp: missing request body writer")
	}
	ch := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, werr := writeAllIOWriter(c.reqBody, data)
		ch <- struct {
			n   int
			err error
		}{n, werr}
	}()
	select {
	case <-ctx.Done():
		_ = c.Close()
		got := <-ch
		_ = got
		if ce := context.Cause(ctx); errors.Is(ce, context.Canceled) {
			return 0, ce
		}
		return 0, os.ErrDeadlineExceeded
	case got := <-ch:
		return got.n, got.err
	}
}

// h2UDPUploadWriter writes framed DATAGRAM capsules to the CONNECT-UDP request body, honoring
// write deadlines the same way as h2ConnectUDPPacketConn.WriteTo (parity with chunked upload).
type h2UDPUploadWriter struct {
	c *h2ConnectUDPPacketConn
}

func (w *h2UDPUploadWriter) Write(b []byte) (int, error) {
	c := w.c
	if c == nil || c.reqBody == nil {
		return 0, fmt.Errorf("masque h2 dataplane connect-udp: missing request body writer")
	}
	dl := c.deadlines.write.Load()
	if dl == 0 {
		// Delegate full io.Writer semantics (including n on error) to writeAllIOWriter.
		return writeAllIOWriter(c.reqBody, b)
	}
	if time.Now().UnixNano() > dl {
		return 0, os.ErrDeadlineExceeded
	}
	wctx, wcancel := context.WithDeadline(context.Background(), time.Unix(0, dl))
	defer wcancel()
	n, err := c.awaitH2UDPReqBodyWrite(wctx, b)
	if err != nil {
		return n, err
	}
	if n != len(b) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

func (c *h2ConnectUDPPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	ctx := context.Background()
	readCancel := func() {}
	if v := c.deadlines.read.Load(); v != 0 {
		if time.Now().UnixNano() > v {
			return 0, nil, os.ErrDeadlineExceeded
		}
		ctx, readCancel = context.WithDeadline(context.Background(), time.Unix(0, v))
	}
	defer readCancel()

	for {
		if c.closed.Load() {
			return 0, nil, net.ErrClosed
		}
		if ctx.Err() != nil {
			switch {
			case errors.Is(ctx.Err(), context.Canceled):
				return 0, nil, context.Canceled
			default:
				return 0, nil, os.ErrDeadlineExceeded
			}
		}
		ct, r, err := c.awaitParseH2UDPResponseCapsule(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, nil, err
			}
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled) {
				return 0, nil, err
			}
			// After a successful CONNECT-UDP, any capsule framing fault leaves the HTTP/2 body stream
			// misaligned; close the tunnel instead of leaving a half-synced reader for further ReadFrom calls.
			_ = c.Close()
			// Use "dataplane" wording so the message does not contain "masque h2:" (handshake class);
			// overlay fallback should not trigger on corrupt streams after a successful CONNECT-UDP.
			return 0, nil, fmt.Errorf("masque h2 dataplane connect-udp capsule: %w", err)
		}
		if ct != capsuleTypeDatagram {
			discardErr := c.awaitDrainNonDatagramCapsule(ctx, r)
			if discardErr != nil {
				if errors.Is(discardErr, os.ErrDeadlineExceeded) || errors.Is(discardErr, context.Canceled) {
					return 0, nil, discardErr
				}
				_ = c.Close()
				return 0, nil, fmt.Errorf("masque h2 dataplane connect-udp non-datagram capsule drain: %w", discardErr)
			}
			continue
		}
		payload, err := c.awaitReadLimitedCapsulePayload(ctx, r)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled) {
				return 0, nil, err
			}
			_ = c.Close()
			return 0, nil, fmt.Errorf("masque h2 dataplane connect-udp capsule body: %w", err)
		}
		udpPayload, ok, perr := ParseMasqueHTTPDatagramUDP(payload)
		// Parity with masque-go proxiedConn.ReadFrom: unreliable MASQUE datagrams — malformed HTTP
		// Datagram payload must not tear down the CONNECT-UDP stream (continue like H3 goto start).
		if perr != nil || !ok {
			continue
		}
		n = copy(p, udpPayload)
		return n, c.remoteAddr, nil
	}
}

func (c *h2ConnectUDPPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if c.deadlines.writeTimeoutExceeded() {
		return 0, os.ErrDeadlineExceeded
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if c.deadlines.writeTimeoutExceeded() {
		return 0, os.ErrDeadlineExceeded
	}

	uw := &h2UDPUploadWriter{c: c}
	if err := writeUDPPayloadAsH2DatagramCapsules(uw, nil, p); err != nil {
		// Match ReadFrom capsule reader / connect-ip writeToStream (connectIPH2CapsulePipeCleanUploadTermination):
		// plain stream end or pipe half-close — no Close(), no wrapper (avoid false http_layer_fallback).
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			return 0, err
		}
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled) {
			return 0, err
		}
		_ = c.Close()
		return 0, fmt.Errorf("masque h2 dataplane connect-udp write body: %w", err)
	}
	return len(p), nil
}

// ParseMasqueHTTPDatagramUDP interprets CONNECT-UDP HTTP Datagram payload (RFC 9297 / MASQUE).
// Return convention matches third_party/masque-go parseProxiedDatagramPayload for H3 parity:
// truncated / empty structural cases use io.EOF; callers drop (do not treat as capsule mis-framing).
func ParseMasqueHTTPDatagramUDP(data []byte) (payload []byte, ok bool, err error) {
	if len(data) == 0 {
		return nil, false, io.EOF
	}
	if data[0] == 0 {
		return data[1:], true, nil
	}
	if data[0]&0xc0 == 0 {
		return nil, false, nil
	}
	if data[0]&0x3f != 0 {
		return nil, false, nil
	}
	switch data[0] >> 6 {
	case 1:
		if len(data) < 2 {
			return nil, false, io.EOF
		}
		if data[1] == 0 {
			return data[2:], true, nil
		}
		return nil, false, nil
	case 2:
		if len(data) < 4 {
			return nil, false, io.EOF
		}
		if data[1] == 0 && data[2] == 0 && data[3] == 0 {
			return data[4:], true, nil
		}
		return nil, false, nil
	case 3:
		if len(data) < 8 {
			return nil, false, io.EOF
		}
		if data[1] == 0 && data[2] == 0 && data[3] == 0 && data[4] == 0 && data[5] == 0 && data[6] == 0 && data[7] == 0 {
			return data[8:], true, nil
		}
		return nil, false, nil
	}
	return nil, false, io.EOF
}

type masqueUDPAddr struct{ s string }

func (m masqueUDPAddr) Network() string { return h2ConnectUDPProto }
func (m masqueUDPAddr) String() string  { return m.s }

func proxyStatusNextHopUDP(rsp *http.Response) *net.UDPAddr {
	if rsp == nil {
		return nil
	}
	vals := rsp.Header.Values("Proxy-Status")
	if len(vals) == 0 {
		return nil
	}
	proxyStatus, err := httpsfv.UnmarshalItem(vals)
	if err != nil {
		return nil
	}
	nextHop, ok := proxyStatus.Params.Get("next-hop")
	if !ok {
		return nil
	}
	nextHopStr, ok := nextHop.(string)
	if !ok || nextHopStr == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(nextHopStr)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	portNum, err := net.LookupPort("udp", port)
	if err != nil {
		return nil
	}
	return &net.UDPAddr{IP: ip, Port: portNum}
}

func (s *coreSession) ensureH2UDPTransport(ctx context.Context) (*http2.Transport, error) {
	if s.options.TCPDial == nil {
		return nil, fmt.Errorf("masque h2: tcp dialer is not configured")
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, context.Cause(ctx)
	}
	s.h2UdpMu.Lock()
	defer s.h2UdpMu.Unlock()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, context.Cause(ctx)
	}
	if s.h2UdpTransport != nil {
		return s.h2UdpTransport, nil
	}
	tlsConf := masqueClientH2TLSConfig(s.options)
	tr := &http2.Transport{
		TLSClientConfig: tlsConf,
		// Parity with http3.Transport DisableCompression: default H2 adds Accept-Encoding: gzip and may
		// transparently decompress Response.Body — fatal for Extended CONNECT capsule/datagram streams.
		DisableCompression: true,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			conn, err := s.options.TCPDial(ctx, network, addr)
			if err != nil {
				return nil, fmt.Errorf("masque h2: tcp dial %s %s: %w", network, addr, err)
			}
			tlsConn := tls.Client(conn, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("masque h2: tls handshake %s %s: %w", network, addr, err)
			}
			return tlsConn, nil
		},
	}
	s.h2UdpTransport = tr
	return tr, nil
}

// resetH2UDPTransportLockedAssumeMu closes the cached HTTP/2 client transport shared by CONNECT-UDP,
// CONNECT-IP, and H2 CONNECT-stream so the next dial establishes a fresh TLS+H2 connection pool.
// Caller must hold s.mu.
func (s *coreSession) resetH2UDPTransportLockedAssumeMu() {
	s.h2UdpMu.Lock()
	if s.h2UdpTransport != nil {
		s.h2UdpTransport.CloseIdleConnections()
		s.h2UdpTransport = nil
	}
	s.h2UdpMu.Unlock()
}

func (s *coreSession) dialUDPOverHTTP2(ctx context.Context, template *uritemplate.Template, target string) (net.PacketConn, error) {
	if hook := s.h2UDPConnectHook; hook != nil {
		return hook(ctx, template, target)
	}
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	default:
	}
	if template == nil {
		return nil, ErrConnectUDPTemplateNotConfigured
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("masque h2: bad target: %w", err)
	}
	expanded, err := template.Expand(uritemplate.Values{
		uriTemplateTargetHostKey: uritemplate.String(host),
		uriTemplateTargetPortKey: uritemplate.String(port),
	})
	if err != nil {
		return nil, fmt.Errorf("masque h2: expand template: %w", err)
	}
	u, err := url.Parse(expanded)
	if err != nil {
		return nil, fmt.Errorf("masque h2: parse url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("masque h2: template must use https scheme")
	}

	tr, err := s.ensureH2UDPTransport(ctx)
	if err != nil {
		return nil, err
	}

	pipeR, pipeW := io.Pipe()
	// Relay parent cancellation only through handshake, then detach on success.
	streamCtx, stopReqCtxRelay := connectip.NewH2ExtendedConnectRequestContext(ctx)
	defer stopReqCtxRelay(false)
	req, err := http.NewRequestWithContext(streamCtx, http.MethodConnect, expanded, &h2ExtendedConnectUploadBody{pipe: pipeR})
	if err != nil {
		_ = pipeW.Close()
		_ = pipeR.Close()
		return nil, fmt.Errorf("masque h2: new connect-udp request: %w", err)
	}
	req.Proto = h2ConnectUDPProto
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.Header.Set(":protocol", h2ConnectUDPProto)
	req.Header.Set(http3.CapsuleProtocolHeader, capsuleProtoHeaderValueH2)
	if t := strings.TrimSpace(s.options.ServerToken); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	req.ContentLength = -1

	resp, err := tr.RoundTrip(req)
	if err != nil {
		_ = pipeW.Close()
		_ = pipeR.Close()
		return nil, fmt.Errorf("masque h2: roundtrip: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = pipeW.Close()
		_ = pipeR.Close()
		_ = resp.Body.Close()
		return nil, fmt.Errorf("masque h2: CONNECT-UDP status %d", resp.StatusCode)
	}
	if ctxErr := context.Cause(ctx); ctxErr != nil {
		_ = pipeW.Close()
		_ = pipeR.Close()
		_ = resp.Body.Close()
		return nil, ctxErr
	}
	stopReqCtxRelay(true)

	portNum := int(s.options.ServerPort)
	if portNum <= 0 {
		portNum = 443
	}
	dialAddr := masqueDialTarget(masqueQuicDialCandidateHost(s.options), portNum)

	raddr := masqueUDPAddr{s: target}
	if nh := proxyStatusNextHopUDP(resp); nh != nil {
		raddr = masqueUDPAddr{s: net.JoinHostPort(nh.IP.String(), strconv.Itoa(nh.Port))}
	}

	conn := &h2ConnectUDPPacketConn{
		reqPipeR:   pipeR,
		reqBody:    pipeW,
		resp:       resp,
		localAddr:  masqueUDPAddr{s: dialAddr},
		remoteAddr: raddr,
	}
	return conn, nil
}

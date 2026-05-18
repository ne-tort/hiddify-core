package masque

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
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
	// h2ConnectUDPResponseBodyBufSize coalesces HTTP/2 CONNECT-UDP response-body reads for RFC 9297
	// capsule parsing (parity ServeH2ConnectUDP br and masque-go prefetch).
	h2ConnectUDPResponseBodyBufSize = 64 * 1024
	// h2ConnectUDPMinDeliveredUDPPayload is the smallest DNS response header (RFC 1035). Shorter
	// non-empty downlink payloads are framing slop or kernel ICMP debris — drop and keep parsing.
	h2ConnectUDPMinDeliveredUDPPayload = 12
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

func flushH2ConnectUDPResponse(w io.Writer) {
	if w == nil {
		return
	}
	// Prefer ResponseController (connect-ip-go flushHTTPResponseBody): on HTTP/2 Extended CONNECT
	// http.Flusher alone may not push RFC 9297 capsules to the peer (bench UDP probe timeout).
	if rw, ok := w.(http.ResponseWriter); ok {
		if err := http.NewResponseController(rw).Flush(); err == nil || errors.Is(err, http.ErrNotSupported) {
			return
		}
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func writeUDPH2ConnectDatagramCapsule(w io.Writer, udpPayload []byte) error {
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
	if rw, ok := w.(http.ResponseWriter); ok {
		flushH2ConnectUDPResponse(rw)
	} else {
		flushH2ConnectUDPRequestBody(w)
	}
	return nil
}

// writeUDPPayloadAsH2DatagramCapsules sends one UDP payload (possibly larger than one RFC 9297
// DATAGRAM capsule allows) as a sequence of capsules, preserving all bytes — parity with the
// client-side masqueUDPDatagramSplitConn chunk size and ServeH2ConnectUDP downlink framing.
func writeUDPPayloadAsH2DatagramCapsules(w io.Writer, udpPayload []byte) error {
	if len(udpPayload) == 0 {
		return writeUDPH2ConnectDatagramCapsule(w, nil)
	}
	step := h2ConnectUDPMaxUDPPayloadPerDatagramCapsule
	for offset := 0; offset < len(udpPayload); {
		end := offset + step
		if end > len(udpPayload) {
			end = len(udpPayload)
		}
		if err := writeUDPH2ConnectDatagramCapsule(w, udpPayload[offset:end]); err != nil {
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

// h2UDPDownlinkItem is one CONNECT-UDP downlink datagram delivered by the background pump.
type h2UDPDownlinkItem struct {
	payload           []byte
	err               error
	icmpPortUnreachable bool
}

type h2ConnectUDPPacketConn struct {
	reqPipeR *io.PipeReader
	reqBody  io.WriteCloser
	resp     *http.Response

	// respBodyBuf coalesces HTTP/2 response-body reads for RFC 9297 capsule framing (parity ServeH2ConnectUDP br).
	respBodyBuf *bufio.Reader

	writeMu sync.Mutex // uplink DATAGRAM capsules (request body)
	readMu  sync.Mutex // downlink capsule parse (response body; connect-ip-go h2CapsulePipeStream parity)

	// downlinkCh is set only for dialed CONNECT-UDP tunnels. A background pump drains the HTTP/2
	// response body while uplink WriteTo runs so the server can flush ICMP/refused capsules without
	// waiting for ReadFrom (bench dig timeout). Unit tests leave downlinkCh nil (sync ReadFrom).
	downlinkCh chan h2UDPDownlinkItem

	deadlines connDeadlines
	closed    atomic.Bool

	primeOnce sync.Once
	primeErr  error

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

func (c *h2ConnectUDPPacketConn) runH2ConnectUDPDownlinkPump() {
	defer close(c.downlinkCh)
	for {
		if c.closed.Load() {
			return
		}
		c.readMu.Lock()
		payload, err := c.readH2ConnectUDPDatagramLocked(context.Background())
		c.readMu.Unlock()
		if c.closed.Load() && err != nil {
			return
		}
		item := h2UDPDownlinkItem{payload: payload, err: err}
		if errors.Is(err, ErrUDPPortUnreachable) {
			item.err = nil
			item.icmpPortUnreachable = true
		}
		select {
		case c.downlinkCh <- item:
		default:
			c.downlinkCh <- item
		}
		if err != nil && !errors.Is(err, ErrUDPPortUnreachable) {
			return
		}
	}
}

func (c *h2ConnectUDPPacketConn) primeH2ConnectUDPStream() error {
	if c == nil || c.reqBody == nil {
		return nil
	}
	c.primeOnce.Do(func() {
		uw := &h2UDPUploadWriter{c: c}
		if err := writeUDPPayloadAsH2DatagramCapsules(uw, nil); err != nil {
			c.primeErr = fmt.Errorf("masque h2 dataplane connect-udp stream prime: %w", err)
		}
	})
	return c.primeErr
}

// readH2ConnectUDPDatagramLocked reads the next RFC 9297 DATAGRAM capsule on the CONNECT-UDP response
// body. Caller must hold readMu. A zero-length UDP payload signals ICMP port-unreachable (bench dig).
func (c *h2ConnectUDPPacketConn) readH2ConnectUDPDatagramLocked(ctx context.Context) ([]byte, error) {
	if c == nil || c.resp == nil || c.resp.Body == nil {
		return nil, fmt.Errorf("masque h2 dataplane connect-udp: missing HTTP response body")
	}
	for {
		if c.closed.Load() {
			return nil, net.ErrClosed
		}
		ct, r, err := c.awaitParseH2UDPResponseCapsule(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, err
			}
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled) {
				return nil, err
			}
			_ = c.Close()
			return nil, fmt.Errorf("masque h2 dataplane connect-udp capsule: %w", err)
		}
		if ct != capsuleTypeDatagram {
			if discardErr := c.awaitDrainNonDatagramCapsule(ctx, r); discardErr != nil {
				if errors.Is(discardErr, os.ErrDeadlineExceeded) || errors.Is(discardErr, context.Canceled) {
					return nil, discardErr
				}
				_ = c.Close()
				return nil, fmt.Errorf("masque h2 dataplane connect-udp non-datagram capsule drain: %w", discardErr)
			}
			continue
		}
		payload, err := c.awaitReadLimitedCapsulePayload(ctx, r)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled) {
				return nil, err
			}
			_ = c.Close()
			return nil, fmt.Errorf("masque h2 dataplane connect-udp capsule body: %w", err)
		}
		udpPayload, ok, perr := ParseMasqueHTTPDatagramUDP(payload)
		if perr != nil || !ok {
			continue
		}
		if len(udpPayload) == 0 {
			return nil, newUDPPortUnreachableError(c.remoteAddr)
		}
		// Dialed tunnels only: drop sub-DNS-header slop (bench dig to TCP-only port).
		if c.downlinkCh != nil && len(udpPayload) < h2ConnectUDPMinDeliveredUDPPayload {
			continue
		}
		dup := make([]byte, len(udpPayload))
		copy(dup, udpPayload)
		return dup, nil
	}
}

// h2UDPResponseCapsuleResult is the asynchronous result of framing one RFC 9297 capsule header on the CONNECT-UDP HTTP/2 response body.
type h2UDPResponseCapsuleResult struct {
	ct  http3.CapsuleType
	r   io.Reader
	err error
}

func (c *h2ConnectUDPPacketConn) responseBodyReader() *bufio.Reader {
	if c.respBodyBuf == nil {
		c.respBodyBuf = bufio.NewReaderSize(c.resp.Body, h2ConnectUDPResponseBodyBufSize)
	}
	return c.respBodyBuf
}

// Read implements net.PacketConn via ReadFrom so stacks that only call Read (not ReadFrom) still
// receive CONNECT-UDP downlink datagrams (bench dig / DNS over TUN).
func (c *h2ConnectUDPPacketConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

func (c *h2ConnectUDPPacketConn) parseH2UDPResponseCapsuleFromBody() (http3.CapsuleType, io.Reader, error) {
	if c.resp == nil || c.resp.Body == nil {
		return 0, nil, fmt.Errorf("masque h2 dataplane connect-udp: missing HTTP response body")
	}
	return parseH2ConnectUDPCapsule(quicvarint.NewReader(c.responseBodyReader()))
}

func (c *h2ConnectUDPPacketConn) awaitParseH2UDPResponseCapsule(ctx context.Context) (http3.CapsuleType, io.Reader, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		return c.parseH2UDPResponseCapsuleFromBody()
	}
	ch := make(chan h2UDPResponseCapsuleResult, 1)
	go func() {
		ct, cr, cerr := c.parseH2UDPResponseCapsuleFromBody()
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

func (c *h2ConnectUDPPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.resp == nil || c.resp.Body == nil {
		return 0, nil, fmt.Errorf("masque h2 dataplane connect-udp: missing HTTP response body")
	}
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	ctx := context.Background()
	readCancel := func() {}
	if v := c.deadlines.read.Load(); v != 0 {
		if time.Now().UnixNano() > v {
			return 0, nil, os.ErrDeadlineExceeded
		}
		ctx, readCancel = context.WithDeadline(context.Background(), time.Unix(0, v))
	}
	defer readCancel()

	if c.downlinkCh != nil {
		select {
		case <-ctx.Done():
			_ = c.Close()
			if ce := context.Cause(ctx); errors.Is(ce, context.Canceled) {
				return 0, nil, ce
			}
			return 0, nil, os.ErrDeadlineExceeded
		case item, ok := <-c.downlinkCh:
			if !ok {
				return 0, nil, net.ErrClosed
			}
			if item.err != nil {
				if c.deadlines.read.Load() != 0 && (errors.Is(item.err, os.ErrDeadlineExceeded) || errors.Is(item.err, context.Canceled)) {
					_ = c.Close()
				}
				return 0, nil, item.err
			}
			if item.icmpPortUnreachable {
				return 0, c.remoteAddr, newUDPPortUnreachableError(c.remoteAddr)
			}
			n := copy(p, item.payload)
			return n, c.remoteAddr, nil
		}
	}

	c.readMu.Lock()
	payload, err := c.readH2ConnectUDPDatagramLocked(ctx)
	c.readMu.Unlock()
	if err != nil {
		if errors.Is(err, ErrUDPPortUnreachable) {
			return 0, c.remoteAddr, newUDPPortUnreachableError(c.remoteAddr)
		}
		if c.deadlines.read.Load() != 0 && (errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled)) {
			_ = c.Close()
		}
		return 0, nil, err
	}
	n := copy(p, payload)
	return n, c.remoteAddr, nil
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
	if err := writeUDPPayloadAsH2DatagramCapsules(uw, p); err != nil {
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
	flushH2ConnectUDPRequestBody(c.reqBody)
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

func (s *coreSession) newMasqueClientH2Transport() *http2.Transport {
	tlsConf := masqueClientH2TLSConfig(s.options)
	dialOverrideHost := strings.TrimSpace(masqueQuicDialCandidateHost(s.options))
	alternateDialHost := ""
	if strings.EqualFold(strings.TrimSpace(s.options.WarpConnectIPProtocol), "cf-connect-ip") {
		alternateDialHost = warpMasqueH2AlternateDialHost(dialOverrideHost)
	}
	dialTLS := func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		dialHostCandidates := h2DialHostCandidates(strings.TrimSpace(s.options.WarpConnectIPProtocol), dialOverrideHost, alternateDialHost)
		var lastErr error
		for _, candidateHost := range dialHostCandidates {
			dialAddr := addr
			if candidateHost != "" {
				if _, p, splitErr := net.SplitHostPort(addr); splitErr == nil {
					dialAddr = net.JoinHostPort(candidateHost, p)
				}
			}
			if strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1" {
				log.Printf("masque h2 tcp dial attempt network=%s addr=%s candidate=%q", network, dialAddr, candidateHost)
			}
			conn, err := s.options.TCPDial(ctx, network, dialAddr)
			if err != nil {
				lastErr = fmt.Errorf("masque h2: tcp dial %s %s: %w", network, dialAddr, err)
				continue
			}
			if s.options.MasqueTCPDialTLS != nil {
				tlsConn, err := s.options.MasqueTCPDialTLS(ctx, conn, cfg.NextProtos, dialAddr)
				if err != nil {
					_ = conn.Close()
					lastErr = fmt.Errorf("masque h2: tls handshake %s %s: %w", network, dialAddr, err)
					continue
				}
				return tlsConn, nil
			}
			tlsConn := tls.Client(conn, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				lastErr = fmt.Errorf("masque h2: tls handshake %s %s: %w", network, dialAddr, err)
				continue
			}
			return tlsConn, nil
		}
		return nil, lastErr
	}
	tr, err := newMasqueBulkHTTP2Transport(tlsConf, dialTLS)
	if err != nil {
		tr = &http2.Transport{
			TLSClientConfig:    tlsConf,
			DisableCompression: true,
			DialTLSContext:     dialTLS,
		}
		applyMasqueBulkHTTP2TransportDefaults(tr)
	}
	return tr
}

func (s *coreSession) ensureH2TransportCached(ctx context.Context, mu *sync.Mutex, slot **http2.Transport) (*http2.Transport, error) {
	if s.options.TCPDial == nil {
		return nil, fmt.Errorf("masque h2: tcp dialer is not configured")
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, context.Cause(ctx)
	}
	mu.Lock()
	defer mu.Unlock()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, context.Cause(ctx)
	}
	if *slot != nil {
		return *slot, nil
	}
	tr := s.newMasqueClientH2Transport()
	*slot = tr
	return tr, nil
}

func (s *coreSession) ensureH2UDPTransport(ctx context.Context) (*http2.Transport, error) {
	return s.ensureH2TransportCached(ctx, &s.h2UdpMu, &s.h2UdpTransport)
}

// ensureH2ConnectStreamTransport uses a dedicated HTTP/2 client pool from CONNECT-UDP/IP so a
// saturated CONNECT-stream iperf run does not exhaust connection-level flow control before the
// post-TCP UDP probe (bench §15.3a).
func (s *coreSession) ensureH2ConnectStreamTransport(ctx context.Context) (*http2.Transport, error) {
	return s.ensureH2TransportCached(ctx, &s.h2ConnectStreamMu, &s.h2ConnectStreamTransport)
}

func closeH2MasqueClientTransport(tr *http2.Transport) {
	if tr != nil {
		tr.CloseIdleConnections()
	}
}

func (s *coreSession) closeAllH2ClientTransports() {
	s.h2UdpMu.Lock()
	closeH2MasqueClientTransport(s.h2UdpTransport)
	s.h2UdpTransport = nil
	s.h2UdpMu.Unlock()
	s.h2ConnectStreamMu.Lock()
	closeH2MasqueClientTransport(s.h2ConnectStreamTransport)
	s.h2ConnectStreamTransport = nil
	s.h2ConnectStreamMu.Unlock()
}

func h2DialHostCandidates(connectProto string, dialOverrideHost string, alternateDialHost string) []string {
	dialOverrideHost = strings.TrimSpace(dialOverrideHost)
	alternateDialHost = strings.TrimSpace(alternateDialHost)
	if dialOverrideHost == "" {
		return []string{""}
	}
	if alternateDialHost == "" || strings.EqualFold(alternateDialHost, dialOverrideHost) {
		return []string{dialOverrideHost}
	}
	if strings.EqualFold(strings.TrimSpace(connectProto), "cf-connect-ip") {
		// For WARP H2, some sibling edges advertise h2 but reject RFC 8441 Extended CONNECT.
		// Force sibling endpoint first (and only) so h2 pool does not pin to a known-bad peer.
		return []string{alternateDialHost}
	}
	return []string{dialOverrideHost, alternateDialHost}
}

// isMasqueH2ExtendedConnectUnsupportedByPeer matches golang.org/x/net/http2 errors when the peer did not
// advertise RFC 8441 (SETTINGS_ENABLE_CONNECT_PROTOCOL). TLS may still succeed on the sibling IPv4.
func isMasqueH2ExtendedConnectUnsupportedByPeer(err error) bool {
	if err == nil {
		return false
	}
	es := strings.ToLower(err.Error())
	return strings.Contains(es, "extended connect not supported") ||
		strings.Contains(es, "enable_connect_protocol") ||
		strings.Contains(es, "enable connect protocol")
}

func warpMasqueH2AlternateDialHost(host string) string {
	host = strings.TrimSpace(host)
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is4() {
		return ""
	}
	v4 := addr.As4()
	switch v4[3] {
	case 1:
		v4[3] = 2
	case 2:
		v4[3] = 1
	default:
		return ""
	}
	return netip.AddrFrom4(v4).String()
}

// resetH2UDPTransportLockedAssumeMu closes the CONNECT-UDP/IP HTTP/2 pool. Caller must hold s.mu.
func (s *coreSession) resetH2UDPTransportLockedAssumeMu() {
	s.h2UdpMu.Lock()
	closeH2MasqueClientTransport(s.h2UdpTransport)
	s.h2UdpTransport = nil
	s.h2UdpMu.Unlock()
}

// resetH2ConnectStreamTransportLockedAssumeMu closes the CONNECT-stream HTTP/2 pool. Caller must hold s.mu.
func (s *coreSession) resetH2ConnectStreamTransportLockedAssumeMu() {
	s.h2ConnectStreamMu.Lock()
	closeH2MasqueClientTransport(s.h2ConnectStreamTransport)
	s.h2ConnectStreamTransport = nil
	s.h2ConnectStreamMu.Unlock()
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
	streamCtx, stopReqCtxRelay := connectip.NewH2ExtendedConnectRequestContext(ctx)
	defer stopReqCtxRelay(false)
	req, err := http.NewRequestWithContext(streamCtx, http.MethodConnect, expanded, &h2ExtendedConnectUploadBody{pipe: pipeR})
	if err != nil {
		_ = pipeW.Close()
		_ = pipeR.Close()
		return nil, fmt.Errorf("masque h2: new connect-udp request: %w", err)
	}
	// Parity h2_connect_stream / connect-ip-go DialHTTP2: RFC 8441 uses :protocol only; do not set
	// req.Proto to "connect-udp" — x/net/http2 treats non-HTTP Proto as a plain (non-Extended) CONNECT
	// and the request DATAGRAM body never reaches the server (bench dig timeout, TCP stream OK).
	req.Header = make(http.Header)
	req.Header.Set(":protocol", h2ConnectUDPProto)
	req.Header.Set(http3.CapsuleProtocolHeader, capsuleProtoHeaderValueH2)
	setMasqueAuthorizationHeader(req.Header, s.options)
	if u.Host != "" {
		req.Host = u.Host
	}
	req.ContentLength = -1

	resp, err := tr.RoundTrip(req)
	if err != nil {
		_ = pipeW.Close()
		_ = pipeR.Close()
		proto := strings.TrimSpace(s.options.WarpConnectIPProtocol)
		primaryHost := strings.TrimSpace(masqueQuicDialCandidateHost(s.options))
		altHost := ""
		if strings.EqualFold(proto, "cf-connect-ip") {
			altHost = warpMasqueH2AlternateDialHost(primaryHost)
		}
		if altHost != "" && isMasqueH2ExtendedConnectUnsupportedByPeer(err) {
			log.Printf("masque h2 cf-connect-ip: connect-udp tcp uses sibling %s of quic dataplane %s; peer omits RFC8441 SETTINGS_ENABLE_CONNECT_PROTOCOL tag=%s",
				altHost, primaryHost, strings.TrimSpace(s.options.Tag))
		}
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

	pc := &h2ConnectUDPPacketConn{
		reqPipeR:   pipeR,
		reqBody:    newH2ConnectUDPRequestBodyWriter(pipeW),
		resp:       resp,
		localAddr:  masqueUDPAddr{s: dialAddr},
		remoteAddr: raddr,
		downlinkCh: make(chan h2UDPDownlinkItem, 64),
	}
	// Drain the response body before any uplink DATA (prime / WriteTo): on WAN paths HTTP/2
	// flow control deadlocks if request capsules are written while the peer response is idle.
	go pc.runH2ConnectUDPDownlinkPump()
	// Prime at dial, not first WriteTo: TUN packetConnectionCopy may start ReadFrom (download)
	// before the upload goroutine runs WriteTo; without an early empty DATAGRAM the server
	// downlink stays blocked on onward UDP Read while the client pump waits on response DATA.
	if err := pc.primeH2ConnectUDPStream(); err != nil {
		_ = pc.Close()
		return nil, err
	}
	return pc, nil
}


package connectudp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

const (
	// h2MinDeliveredUDPPayload is the smallest DNS response header (RFC 1035). Shorter
	// non-empty downlink payloads are framing slop or kernel ICMP debris — drop and keep parsing.
	h2MinDeliveredUDPPayload = 12
)

// H2DownlinkItem is one CONNECT-UDP downlink datagram delivered by the background pump.
type H2DownlinkItem struct {
	Payload             []byte
	Err                 error
	ICMPPortUnreachable bool
}

// H2PacketConnConfig wires a dialed or test CONNECT-UDP HTTP/2 tunnel.
type H2PacketConnConfig struct {
	ReqPipeR      *io.PipeReader
	ReqBody       io.WriteCloser
	Resp          *http.Response
	LocalAddr     net.Addr
	RemoteAddr    net.Addr
	AsyncDownlink bool // buffered pump; caller must RunDownlinkPump
}

// H2PacketConn is the client CONNECT-UDP net.PacketConn over HTTP/2 DATAGRAM capsules.
type H2PacketConn struct {
	reqPipeR *io.PipeReader
	reqBody  io.WriteCloser
	resp     *http.Response

	respBodyBuf *bufio.Reader

	writeMu sync.Mutex
	readMu  sync.Mutex

	downlinkCh chan H2DownlinkItem

	deadlines connDeadlines
	closed    atomic.Bool

	primeOnce sync.Once
	primeErr  error

	localAddr  net.Addr
	remoteAddr net.Addr
}

// NewH2PacketConn builds a CONNECT-UDP packet conn. When AsyncDownlink is set, call RunDownlinkPump.
func NewH2PacketConn(cfg H2PacketConnConfig) *H2PacketConn {
	c := &H2PacketConn{
		reqPipeR:   cfg.ReqPipeR,
		reqBody:    cfg.ReqBody,
		resp:       cfg.Resp,
		localAddr:  cfg.LocalAddr,
		remoteAddr: cfg.RemoteAddr,
	}
	if cfg.AsyncDownlink {
		c.downlinkCh = make(chan H2DownlinkItem, 64)
	}
	return c
}

// IsClosed reports whether Close has been called (test hook).
func (c *H2PacketConn) IsClosed() bool { return c.closed.Load() }

func (c *H2PacketConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *H2PacketConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *H2PacketConn) SetDeadline(t time.Time) error {
	c.deadlines.setDeadline(t)
	return nil
}

func (c *H2PacketConn) SetReadDeadline(t time.Time) error {
	c.deadlines.setReadDeadline(t)
	return nil
}

func (c *H2PacketConn) SetWriteDeadline(t time.Time) error {
	c.deadlines.setWriteDeadline(t)
	return nil
}

func (c *H2PacketConn) Close() error {
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

// RunDownlinkPump drains the HTTP/2 response body while uplink WriteTo runs.
func (c *H2PacketConn) RunDownlinkPump() {
	defer close(c.downlinkCh)
	for {
		if c.closed.Load() {
			return
		}
		c.readMu.Lock()
		payload, err := c.readH2DatagramLocked(context.Background())
		c.readMu.Unlock()
		if c.closed.Load() && err != nil {
			return
		}
		item := H2DownlinkItem{Payload: payload, Err: err}
		if errors.Is(err, ErrPortUnreachable) {
			item.Err = nil
			item.ICMPPortUnreachable = true
		}
		select {
		case c.downlinkCh <- item:
		default:
			c.downlinkCh <- item
		}
		if err != nil && !errors.Is(err, ErrPortUnreachable) {
			return
		}
	}
}

// Prime sends an empty DATAGRAM capsule at dial before first WriteTo.
func (c *H2PacketConn) Prime() error {
	if c == nil || c.reqBody == nil {
		return nil
	}
	c.primeOnce.Do(func() {
		uw := &h2UploadWriter{c: c}
		if err := h2c.WriteUDPPayloadAsDatagramCapsules(uw, nil); err != nil {
			c.primeErr = fmt.Errorf("masque h2 dataplane connect-udp stream prime: %w", err)
		}
	})
	return c.primeErr
}

func (c *H2PacketConn) readH2DatagramLocked(ctx context.Context) ([]byte, error) {
	if c == nil || c.resp == nil || c.resp.Body == nil {
		return nil, fmt.Errorf("masque h2 dataplane connect-udp: missing HTTP response body")
	}
	for {
		if c.closed.Load() {
			return nil, net.ErrClosed
		}
		ct, r, err := c.awaitParseResponseCapsule(ctx)
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
		if ct != h2c.CapsuleTypeDatagram {
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
		udpPayload, ok, perr := ParseHTTPDatagramUDP(payload)
		if perr != nil || !ok {
			continue
		}
		if len(udpPayload) == 0 {
			return nil, NewPortUnreachableError(c.remoteAddr)
		}
		if c.downlinkCh != nil && len(udpPayload) < h2MinDeliveredUDPPayload {
			continue
		}
		dup := make([]byte, len(udpPayload))
		copy(dup, udpPayload)
		return dup, nil
	}
}

type h2ResponseCapsuleResult struct {
	ct  h2c.CapsuleType
	r   io.Reader
	err error
}

func (c *H2PacketConn) responseBodyReader() *bufio.Reader {
	if c.respBodyBuf == nil {
		c.respBodyBuf = bufio.NewReaderSize(c.resp.Body, H2ResponseBodyBufSize)
	}
	return c.respBodyBuf
}

func (c *H2PacketConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

func (c *H2PacketConn) parseResponseCapsuleFromBody() (h2c.CapsuleType, io.Reader, error) {
	if c.resp == nil || c.resp.Body == nil {
		return 0, nil, fmt.Errorf("masque h2 dataplane connect-udp: missing HTTP response body")
	}
	return h2c.ParseCapsule(quicvarint.NewReader(c.responseBodyReader()))
}

func (c *H2PacketConn) awaitParseResponseCapsule(ctx context.Context) (h2c.CapsuleType, io.Reader, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		return c.parseResponseCapsuleFromBody()
	}
	ch := make(chan h2ResponseCapsuleResult, 1)
	go func() {
		ct, cr, cerr := c.parseResponseCapsuleFromBody()
		ch <- h2ResponseCapsuleResult{ct: ct, r: cr, err: cerr}
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

func (c *H2PacketConn) awaitReadLimitedCapsulePayload(ctx context.Context, r io.Reader) ([]byte, error) {
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

func (c *H2PacketConn) awaitDrainNonDatagramCapsule(ctx context.Context, r io.Reader) error {
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

func (c *H2PacketConn) awaitReqBodyWrite(ctx context.Context, data []byte) (int, error) {
	if c.reqBody == nil {
		return 0, fmt.Errorf("masque h2 dataplane connect-udp: missing request body writer")
	}
	ch := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, werr := h2c.WriteAll(c.reqBody, data)
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

type h2UploadWriter struct {
	c *H2PacketConn
}

func (w *h2UploadWriter) Write(b []byte) (int, error) {
	c := w.c
	if c == nil || c.reqBody == nil {
		return 0, fmt.Errorf("masque h2 dataplane connect-udp: missing request body writer")
	}
	dl := c.deadlines.write.Load()
	if dl == 0 {
		return h2c.WriteAll(c.reqBody, b)
	}
	if time.Now().UnixNano() > dl {
		return 0, os.ErrDeadlineExceeded
	}
	wctx, wcancel := context.WithDeadline(context.Background(), time.Unix(0, dl))
	defer wcancel()
	n, err := c.awaitReqBodyWrite(wctx, b)
	if err != nil {
		return n, err
	}
	if n != len(b) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

func (c *H2PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
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
			if item.Err != nil {
				if c.deadlines.read.Load() != 0 && (errors.Is(item.Err, os.ErrDeadlineExceeded) || errors.Is(item.Err, context.Canceled)) {
					_ = c.Close()
				}
				return 0, nil, item.Err
			}
			if item.ICMPPortUnreachable {
				return 0, c.remoteAddr, NewPortUnreachableError(c.remoteAddr)
			}
			n := copy(p, item.Payload)
			return n, c.remoteAddr, nil
		}
	}

	c.readMu.Lock()
	payload, err := c.readH2DatagramLocked(ctx)
	c.readMu.Unlock()
	if err != nil {
		if errors.Is(err, ErrPortUnreachable) {
			return 0, c.remoteAddr, NewPortUnreachableError(c.remoteAddr)
		}
		if c.deadlines.read.Load() != 0 && (errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled)) {
			_ = c.Close()
		}
		return 0, nil, err
	}
	n := copy(p, payload)
	return n, c.remoteAddr, nil
}

func (c *H2PacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
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
	uw := &h2UploadWriter{c: c}
	if err := h2c.WriteUDPPayloadAsDatagramCapsules(uw, p); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			return 0, err
		}
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled) {
			return 0, err
		}
		_ = c.Close()
		return 0, fmt.Errorf("masque h2 dataplane connect-udp write body: %w", err)
	}
	h2c.FlushRequestBody(c.reqBody)
	return len(p), nil
}

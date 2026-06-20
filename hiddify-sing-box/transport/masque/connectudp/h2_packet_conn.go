package connectudp

import (
	"bufio"
	"bytes"
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

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

const (
	// h2MinDeliveredUDPPayload is the smallest DNS response header (RFC 1035). Shorter
	// non-empty downlink payloads are framing slop or kernel ICMP debris — drop and keep parsing.
	h2MinDeliveredUDPPayload = 12
	// h2UploadWriteInterruptDeadline: await+goroutine only when write deadline is this close.
	h2UploadWriteInterruptDeadline = 100 * time.Millisecond
	// h2UploadCoalesceDuplexBytes batches less on C2S when S2C ReadFrom is active (H2 bidi interleave).
	h2UploadCoalesceDuplexBytes = 32 * 1024
	// h2UploadCoalesceThreshold is the upload-only coalesce ceiling (512 KiB).
	h2UploadCoalesceThreshold = 512 * 1024
	// h2UploadBulkEnterGap: WriteTo closer than this counts toward bulk coalesce (echo flood / upload-only).
	h2UploadBulkEnterGap = 50 * time.Microsecond
	// h2UploadBulkExitGap: spaced WriteTo in duplex leaves bulk (pipeline-1 / TUN RTT).
	h2UploadBulkExitGap = 500 * time.Microsecond
	// h2UploadBulkEnterHits: consecutive rapid WriteTo before bulk coalesce arms.
	h2UploadBulkEnterHits = 4
)

// H2PacketConnConfig wires a dialed or test CONNECT-UDP HTTP/2 tunnel.
type H2PacketConnConfig struct {
	ReqPipeR      *io.PipeReader
	ReqBody       io.WriteCloser
	Resp          *http.Response
	LocalAddr     net.Addr
	RemoteAddr    net.Addr
	AsyncDownlink bool // background body reader; caller may RunDownlinkPump
}

// H2PacketConn is the client CONNECT-UDP net.PacketConn over HTTP/2 DATAGRAM capsules.
type H2PacketConn struct {
	reqPipeR *io.PipeReader
	reqBody  io.WriteCloser
	resp     *http.Response

	respBodyBuf *bufio.Reader
	// downlinkPending holds unconsumed RFC9297 wire bytes (parity relayH2ConnectUDPUplink scan).
	downlinkPending []byte
	// downlinkQueue holds parsed UDP payloads ready for ReadFrom (batch fill after body read).
	downlinkQueue [][]byte

	writeMu sync.Mutex
	readMu  sync.Mutex
	// bodyReadMu serializes bufio reads (async pump vs sync ReadFrom).
	bodyReadMu sync.Mutex
	// downlinkReady wakes ReadFrom when the async pump appends body bytes.
	downlinkReady sync.Cond

	asyncDownlink   bool
	downlinkPumpErr error
	downlinkPumpDone bool

	// uploadPending holds encoded RFC9297 wire bytes (server H2ResponseWriter parity).
	uploadPending     bytes.Buffer
	uploadFlushTimer  *time.Timer
	uploadFlushTimerC chan struct{}

	pumpOnce sync.Once
	pumpActive atomic.Bool

	// downlinkReadBuf reused for body reads (avoid per-ReadFrom heap alloc).
	downlinkReadBuf []byte

	deadlines    connDeadlines
	closed       atomic.Bool
	duplexActive atomic.Bool

	lastUploadAt    time.Time
	rapidUploadHits int
	bulkUpload      bool

	primeOnce sync.Once
	primeErr  error

	localAddr  net.Addr
	remoteAddr net.Addr
}

// NewH2PacketConn builds a CONNECT-UDP packet conn. When AsyncDownlink is set, call RunDownlinkPump.
func NewH2PacketConn(cfg H2PacketConnConfig) *H2PacketConn {
	c := &H2PacketConn{
		reqPipeR:      cfg.ReqPipeR,
		reqBody:       cfg.ReqBody,
		resp:          cfg.Resp,
		localAddr:     cfg.LocalAddr,
		remoteAddr:    cfg.RemoteAddr,
		asyncDownlink: cfg.AsyncDownlink,
	}
	c.downlinkReady.L = &c.readMu
	return c
}

// IsClosed reports whether Close has been called (test hook).
func (c *H2PacketConn) IsClosed() bool { return c.closed.Load() }

func (c *H2PacketConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *H2PacketConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *H2PacketConn) SetDeadline(t time.Time) error {
	c.deadlines.setDeadline(t)
	c.downlinkReady.Broadcast()
	return nil
}

func (c *H2PacketConn) SetReadDeadline(t time.Time) error {
	c.deadlines.setReadDeadline(t)
	c.downlinkReady.Broadcast()
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
	c.downlinkReady.Broadcast()
	c.writeMu.Lock()
	wire := c.takeUploadPendingLocked()
	c.writeMu.Unlock()
	if err := c.flushUploadWire(wire); err != nil {
		return err
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

// RunDownlinkPump starts the background body reader (explicit / tests).
func (c *H2PacketConn) RunDownlinkPump() {
	c.startDownlinkPump()
}

func (c *H2PacketConn) ensureDownlinkPump() {
	if !c.downlinkNeedsAsyncPump() {
		return
	}
	c.startDownlinkPump()
}

func (c *H2PacketConn) startDownlinkPump() {
	if c == nil || !c.asyncDownlink {
		return
	}
	c.pumpOnce.Do(func() {
		c.pumpActive.Store(true)
		go c.runDownlinkPump()
	})
}

func (c *H2PacketConn) uploadInFlightLocked() bool {
	return c.uploadPending.Len() > 0 || c.uploadFlushTimer != nil
}

func (c *H2PacketConn) downlinkNeedsAsyncPump() bool {
	if c == nil || !c.asyncDownlink {
		return false
	}
	c.writeMu.Lock()
	inFlight := c.uploadInFlightLocked()
	c.writeMu.Unlock()
	return inFlight
}

func (c *H2PacketConn) downlinkReadScratch() []byte {
	if cap(c.downlinkReadBuf) < H2ResponseBodyBufSize {
		c.downlinkReadBuf = make([]byte, H2ResponseBodyBufSize)
	}
	return c.downlinkReadBuf
}

func (c *H2PacketConn) runDownlinkPump() {
	readBuf := c.downlinkReadScratch()
	defer func() {
		c.readMu.Lock()
		c.downlinkPumpDone = true
		c.downlinkReady.Broadcast()
		c.readMu.Unlock()
	}()
	for {
		if c.closed.Load() {
			return
		}
		nr, err := c.readResponseBodyChunk(context.Background(), readBuf)
		c.readMu.Lock()
		if nr > 0 {
			c.downlinkPending = append(c.downlinkPending, readBuf[:nr]...)
			c.downlinkReady.Broadcast()
			c.readMu.Unlock()
			continue
		}
		if err != nil {
			if c.closed.Load() {
				c.readMu.Unlock()
				return
			}
			if errors.Is(err, io.EOF) {
				if len(c.downlinkPending) > 0 {
					c.downlinkPumpErr = fmt.Errorf("masque h2 dataplane connect-udp capsule: %w", io.ErrUnexpectedEOF)
				}
				c.readMu.Unlock()
				return
			}
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled) {
				c.readMu.Unlock()
				continue
			}
			c.downlinkPumpErr = err
			c.readMu.Unlock()
			return
		}
		c.readMu.Unlock()
	}
}

// Prime sends an empty DATAGRAM capsule at dial before first WriteTo.
func (c *H2PacketConn) Prime() error {
	if c == nil || c.reqBody == nil {
		return nil
	}
	c.primeOnce.Do(func() {
		c.writeMu.Lock()
		wire := c.takeUploadPendingLocked()
		c.writeMu.Unlock()
		if err := c.flushUploadWire(wire); err != nil {
			c.primeErr = fmt.Errorf("masque h2 dataplane connect-udp stream prime flush: %w", err)
			return
		}
		if err := c.writeEmptyDatagramCapsule(); err != nil {
			c.primeErr = fmt.Errorf("masque h2 dataplane connect-udp stream prime: %w", err)
		}
	})
	return c.primeErr
}

func (c *H2PacketConn) fillDownlinkQueueFromPendingLocked() (icmp bool, err error) {
	for len(c.downlinkPending) > 0 {
		inner, consumed, perr := h2c.ParseNextDatagramCapsuleWire(c.downlinkPending)
		if perr != nil {
			_ = c.Close()
			return false, fmt.Errorf("masque h2 dataplane connect-udp capsule: %w", perr)
		}
		if consumed == 0 {
			break
		}
		c.downlinkPending = c.downlinkPending[consumed:]
		if inner == nil {
			continue
		}
		udpPayload, ok, uerr := ParseHTTPDatagramUDP(inner)
		if uerr != nil || !ok {
			continue
		}
		if len(udpPayload) == 0 {
			return true, nil
		}
		if c.asyncDownlink && len(udpPayload) < h2MinDeliveredUDPPayload {
			continue
		}
		c.downlinkQueue = append(c.downlinkQueue, append([]byte(nil), udpPayload...))
	}
	if len(c.downlinkPending) == 0 && cap(c.downlinkPending) > H2ResponseBodyBufSize*2 {
		c.downlinkPending = nil
	}
	return false, nil
}

func (c *H2PacketConn) tryParseOneDatagramInto(p []byte) (n int, icmp bool, err error) {
	if len(c.downlinkQueue) == 0 && len(c.downlinkPending) > 0 {
		icmp, err = c.fillDownlinkQueueFromPendingLocked()
		if icmp || err != nil {
			return 0, icmp, err
		}
	}
	if len(c.downlinkQueue) > 0 {
		payload := c.downlinkQueue[0]
		c.downlinkQueue = c.downlinkQueue[1:]
		if len(c.downlinkQueue) == 0 {
			c.downlinkQueue = nil
		}
		return copy(p, payload), false, nil
	}
	return 0, false, nil
}

func (c *H2PacketConn) readH2DatagramIntoLocked(p []byte, ctx context.Context) (int, error) {
	if c == nil || c.resp == nil || c.resp.Body == nil {
		return 0, fmt.Errorf("masque h2 dataplane connect-udp: missing HTTP response body")
	}
	readBuf := c.downlinkReadScratch()
	var deadlineTimer *time.Timer
	var deadlineC <-chan time.Time
	if dl, ok := ctx.Deadline(); ok {
		deadlineTimer = time.NewTimer(time.Until(dl))
		deadlineC = deadlineTimer.C
		defer deadlineTimer.Stop()
	}
	for {
		if c.closed.Load() {
			return 0, net.ErrClosed
		}
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.Canceled) {
				return 0, err
			}
			return 0, os.ErrDeadlineExceeded
		}
		if n, icmp, err := c.tryParseOneDatagramInto(p); err != nil {
			return 0, err
		} else if icmp {
			return 0, ErrPortUnreachable
		} else if n > 0 {
			return n, nil
		}
		if c.pumpActive.Load() {
			if c.downlinkPumpDone {
				if c.downlinkPumpErr != nil {
					return 0, c.downlinkPumpErr
				}
				return 0, io.EOF
			}
			select {
			case <-deadlineC:
				_ = c.Close()
				if ce := context.Cause(ctx); errors.Is(ce, context.Canceled) {
					return 0, ce
				}
				return 0, os.ErrDeadlineExceeded
			default:
				c.downlinkReady.Wait()
			}
			continue
		}
		nr, err := c.readResponseBodyChunk(ctx, readBuf)
		if nr > 0 {
			c.downlinkPending = append(c.downlinkPending, readBuf[:nr]...)
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(c.downlinkPending) > 0 {
					_ = c.Close()
					return 0, fmt.Errorf("masque h2 dataplane connect-udp capsule: %w", io.ErrUnexpectedEOF)
				}
				return 0, err
			}
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled) {
				return 0, err
			}
			_ = c.Close()
			return 0, err
		}
	}
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

func (c *H2PacketConn) readResponseBodyChunk(ctx context.Context, p []byte) (int, error) {
	c.bodyReadMu.Lock()
	defer c.bodyReadMu.Unlock()
	br := c.responseBodyReader()
	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		return br.Read(p)
	}
	ch := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := br.Read(p)
		ch <- struct {
			n   int
			err error
		}{n, err}
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
	if c.deadlines.writeTimeoutExceeded() {
		return 0, os.ErrDeadlineExceeded
	}
	return h2c.WriteAll(c.reqBody, b)
}

func (c *H2PacketConn) armUploadFlushTimerLocked() {
	if c.uploadFlushTimer != nil {
		return
	}
	c.uploadFlushTimerC = make(chan struct{})
	timerC := c.uploadFlushTimerC
	c.uploadFlushTimer = time.AfterFunc(H2DownlinkCoalesceMaxDelay, func() {
		c.writeMu.Lock()
		if c.uploadFlushTimerC != timerC || c.closed.Load() {
			c.writeMu.Unlock()
			return
		}
		wire := c.takeUploadPendingLocked()
		c.writeMu.Unlock()
		if err := c.flushUploadWire(wire); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				return
			}
			_ = c.Close()
		}
	})
}

func (c *H2PacketConn) stopUploadFlushTimerLocked() {
	if c.uploadFlushTimer != nil {
		c.uploadFlushTimer.Stop()
		c.uploadFlushTimer = nil
	}
	c.uploadFlushTimerC = nil
}

func (c *H2PacketConn) takeUploadPendingLocked() []byte {
	c.stopUploadFlushTimerLocked()
	if c.uploadPending.Len() == 0 {
		return nil
	}
	wire := append([]byte(nil), c.uploadPending.Bytes()...)
	c.uploadPending.Reset()
	return wire
}

func (c *H2PacketConn) flushUploadWire(wire []byte) error {
	if len(wire) == 0 {
		return nil
	}
	return c.writeUploadWireUnlocked(wire)
}

func (c *H2PacketConn) writeEmptyDatagramCapsule() error {
	if c.reqBody == nil {
		return fmt.Errorf("masque h2 dataplane connect-udp: missing request body writer")
	}
	if c.deadlines.writeTimeoutExceeded() {
		return os.ErrDeadlineExceeded
	}
	writeFn := func() error {
		if err := h2c.WriteDatagramCapsule(c.reqBody, nil); err != nil {
			return err
		}
		h2c.FlushRequestBody(c.reqBody)
		return nil
	}
	if !c.uploadWriteNeedsInterrupt() {
		return writeFn()
	}
	ctx, cancel := c.writeDeadlineContext()
	defer cancel()
	return c.awaitWriteReqBody(ctx, writeFn)
}

func (c *H2PacketConn) uploadWriteNeedsInterrupt() bool {
	v := c.deadlines.write.Load()
	if v == 0 {
		return false
	}
	return time.Until(time.Unix(0, v)) <= h2UploadWriteInterruptDeadline
}

func (c *H2PacketConn) writeUploadWireSync(wire []byte) error {
	if _, err := h2c.WriteAll(c.reqBody, wire); err != nil {
		return err
	}
	h2c.FlushRequestBody(c.reqBody)
	return nil
}

func (c *H2PacketConn) writeDeadlineContext() (context.Context, context.CancelFunc) {
	if c.deadlines.writeTimeoutExceeded() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, func() {}
	}
	if v := c.deadlines.write.Load(); v != 0 {
		return context.WithDeadline(context.Background(), time.Unix(0, v))
	}
	return context.Background(), func() {}
}

func (c *H2PacketConn) writeUploadWireUnlocked(wire []byte) error {
	if c == nil || c.reqBody == nil || len(wire) == 0 {
		return nil
	}
	if c.deadlines.writeTimeoutExceeded() {
		return os.ErrDeadlineExceeded
	}
	if !c.uploadWriteNeedsInterrupt() {
		return c.writeUploadWireSync(wire)
	}
	ctx, cancel := c.writeDeadlineContext()
	defer cancel()
	return c.awaitWriteReqBody(ctx, func() error {
		return c.writeUploadWireSync(wire)
	})
}

func (c *H2PacketConn) awaitWriteReqBody(ctx context.Context, writeFn func() error) error {
	ch := make(chan error, 1)
	go func() {
		ch <- writeFn()
	}()
	select {
	case <-ctx.Done():
		if c.reqBody != nil {
			_ = c.reqBody.Close()
		}
		<-ch
		c.closed.Store(true)
		if ce := context.Cause(ctx); errors.Is(ce, context.Canceled) {
			return ce
		}
		return os.ErrDeadlineExceeded
	case err := <-ch:
		return err
	}
}

func (c *H2PacketConn) uploadCoalesceThreshold() int {
	if c != nil && c.duplexActive.Load() {
		return h2UploadCoalesceDuplexBytes
	}
	return h2UploadCoalesceThreshold
}

func (c *H2PacketConn) noteUploadArrivalLocked(now time.Time) {
	if !c.lastUploadAt.IsZero() {
		gap := now.Sub(c.lastUploadAt)
		switch {
		case gap <= h2UploadBulkEnterGap:
			c.rapidUploadHits++
			if c.rapidUploadHits >= h2UploadBulkEnterHits {
				c.bulkUpload = true
			}
		case gap >= h2UploadBulkExitGap:
			c.bulkUpload = false
			c.rapidUploadHits = 0
		default:
			c.rapidUploadHits = 0
		}
	}
	c.lastUploadAt = now
}

func (c *H2PacketConn) uploadFlushInteractiveLocked() bool {
	return c.duplexActive.Load() && !c.bulkUpload
}

func (c *H2PacketConn) flushUploadPendingForRead() error {
	c.writeMu.Lock()
	wire := c.takeUploadPendingLocked()
	c.writeMu.Unlock()
	if len(wire) == 0 {
		return nil
	}
	if err := c.flushUploadWire(wire); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			return err
		}
		_ = c.Close()
		return fmt.Errorf("masque h2 dataplane connect-udp read wake flush: %w", err)
	}
	return nil
}

func (c *H2PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.resp == nil || c.resp.Body == nil {
		return 0, nil, fmt.Errorf("masque h2 dataplane connect-udp: missing HTTP response body")
	}
	if c.downlinkNeedsAsyncPump() {
		c.ensureDownlinkPump()
	}
	c.duplexActive.Store(true)
	if err := c.flushUploadPendingForRead(); err != nil {
		return 0, nil, err
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

	c.readMu.Lock()
	n, err := c.readH2DatagramIntoLocked(p, ctx)
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
	if c.closed.Load() {
		c.writeMu.Unlock()
		return 0, net.ErrClosed
	}
	if c.deadlines.writeTimeoutExceeded() {
		c.writeMu.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
	if len(p) == 0 {
		pending := c.takeUploadPendingLocked()
		c.writeMu.Unlock()
		if err := c.flushUploadWire(pending); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				return 0, err
			}
			_ = c.Close()
			return 0, fmt.Errorf("masque h2 dataplane connect-udp write body: %w", err)
		}
		if err := c.writeEmptyDatagramCapsule(); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				return 0, err
			}
			_ = c.Close()
			return 0, fmt.Errorf("masque h2 dataplane connect-udp write body: %w", err)
		}
		return 0, nil
	}
	if err := h2c.AppendUDPPayloadAsDatagramCapsules(&c.uploadPending, p); err != nil {
		c.writeMu.Unlock()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			return 0, err
		}
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled) {
			return 0, err
		}
		_ = c.Close()
		return 0, fmt.Errorf("masque h2 dataplane connect-udp encode body: %w", err)
	}
	if c.duplexActive.Load() {
		c.noteUploadArrivalLocked(time.Now())
	}
	var wire []byte
	switch {
	case c.uploadFlushInteractiveLocked():
		wire = c.takeUploadPendingLocked()
	case c.uploadPending.Len() >= c.uploadCoalesceThreshold():
		wire = c.takeUploadPendingLocked()
	default:
		c.armUploadFlushTimerLocked()
	}
	c.writeMu.Unlock()
	if len(wire) > 0 {
		if err := c.flushUploadWire(wire); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				return 0, err
			}
			_ = c.Close()
			return 0, fmt.Errorf("masque h2 dataplane connect-udp flush body: %w", err)
		}
	}
	if c.duplexActive.Load() {
		c.ensureDownlinkPump()
	}
	return len(p), nil
}

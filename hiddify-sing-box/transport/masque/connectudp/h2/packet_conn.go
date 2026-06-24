package h2

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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	"github.com/sagernet/sing-box/transport/masque/connectudp/split"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

const (
	// ResponseBodyBufSize coalesces HTTP/2 CONNECT-UDP response-body reads for RFC 9297 capsule parsing.
	ResponseBodyBufSize = 256 * 1024
	// h2UploadCoalesceMaxDelay bounds latency when upload coalesce stays below threshold.
	h2UploadCoalesceMaxDelay = 2 * time.Millisecond
	// h2MinDeliveredUDPPayload is the smallest DNS response header (RFC 1035). Shorter
	// non-empty downlink payloads are framing slop or kernel ICMP debris — drop and keep parsing.
	h2MinDeliveredUDPPayload = 12
	// h2UploadWriteInterruptDeadline: await+goroutine only when write deadline is this close.
	h2UploadWriteInterruptDeadline = 100 * time.Millisecond
	// h2UploadCoalesceDuplexBytes batches less on C2S when S2C ReadFrom is active (H2 bidi interleave).
	h2UploadCoalesceDuplexBytes = 32 * 1024
	// h2UploadCoalesceBulkBytesDefault is prod upload-leg / bulk coalesce ceiling (Docker KPI parity).
	h2UploadCoalesceBulkBytesDefault = 64 * 1024
	// h2UploadCoalesceThreshold is the upload-only coalesce ceiling (128 KiB — balance pipe block vs flush rate).
	h2UploadCoalesceThreshold = 128 * 1024
	envH2UploadCoalesceBulkBytes = "MASQUE_H2_UPLOAD_COALESCE_BULK_BYTES"
	// h2UploadBulkEnterGap: WriteTo closer than this counts toward bulk coalesce (echo flood / upload-only).
	h2UploadBulkEnterGap = 50 * time.Microsecond
	// h2UploadBulkExitGap: spaced WriteTo in duplex leaves bulk (pipeline-1 / TUN RTT).
	h2UploadBulkExitGap = 500 * time.Microsecond
	// h2UploadBidiSafeFlushBytes: large single WriteTo before first ReadFrom must not
	// flush entirely inside ReadFrom (H2 bidi request/response deadlock on big pending).
	h2UploadBidiSafeFlushBytes = 1024
	// h2UploadBulkEnterHits: consecutive rapid WriteTo before bulk coalesce arms.
	h2UploadBulkEnterHits = 4
)

var (
	h2UploadCoalesceBulkBytes     = h2UploadCoalesceBulkBytesDefault
	h2UploadCoalesceBulkBytesInit sync.Once
)

func h2UploadCoalesceBulkBytesConfigured() int {
	h2UploadCoalesceBulkBytesInit.Do(func() {
		if v := strings.TrimSpace(os.Getenv(envH2UploadCoalesceBulkBytes)); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= h2UploadCoalesceDuplexBytes {
				h2UploadCoalesceBulkBytes = n
			}
		}
	})
	return h2UploadCoalesceBulkBytes
}

type PacketConnConfig struct {
	ReqPipeR      io.Closer
	ReqBody       io.WriteCloser
	Resp          *http.Response
	LocalAddr     net.Addr
	RemoteAddr    net.Addr
	AsyncDownlink bool // background body reader; caller may RunDownlinkPump
	UploadOnly    bool // C2S leg; drain response body (asymmetric upload pool)
	LegProfile    LegProfile
	UploadWireAck h2c.ConnectUploadWireAck
	OnClose       func()
}

// PacketConn is the client CONNECT-UDP net.PacketConn over HTTP/2 DATAGRAM capsules.
type PacketConn struct {
	reqPipeR io.Closer
	reqBody  io.WriteCloser
	resp     *http.Response

	respBodyBuf *bufio.Reader
	// downlinkPending holds unconsumed RFC9297 wire bytes (parity relayH2ConnectUDPUplink scan).
	downlinkPending []byte
	// downlinkQueue holds parsed UDP payload views into downlinkPending (zero-copy; drained before pending reuse).
	downlinkQueue [][]byte

	writeMu sync.Mutex
	readMu  sync.Mutex
	// bodyReadMu serializes bufio reads (async pump vs sync ReadFrom).
	bodyReadMu sync.Mutex
	// downlinkReady wakes ReadFrom when the async pump appends body bytes.
	downlinkReady sync.Cond

	asyncDownlink   bool
	uploadOnly      bool
	legProfile      LegProfile
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

	deadlines    split.ConnDeadlines
	closed       atomic.Bool
	closeOnce    sync.Once
	duplexActive atomic.Bool
	// payloadWritePending: last WriteTo carried UDP payload — next ReadFrom uses sync S2C (echo/interactive).
	payloadWritePending atomic.Bool

	lastUploadAt    time.Time
	rapidUploadHits int
	bulkUpload      bool
	// writesSinceRead counts payload WriteTo since last ReadFrom (upload-only never resets → coalesce after first flush).
	writesSinceRead int

	primeOnce sync.Once
	primeErr  error

	uploadWireAck       h2c.ConnectUploadWireAck
	uploadWireCommitted atomic.Int64

	localAddr  net.Addr
	remoteAddr net.Addr
	onClose    func()
}

// NewPacketConn builds a CONNECT-UDP packet conn. When AsyncDownlink is set, call RunDownlinkPump.
func NewPacketConn(cfg PacketConnConfig) *PacketConn {
	c := &PacketConn{
		reqPipeR:      cfg.ReqPipeR,
		reqBody:       cfg.ReqBody,
		resp:          cfg.Resp,
		localAddr:     cfg.LocalAddr,
		remoteAddr:    cfg.RemoteAddr,
		asyncDownlink: cfg.AsyncDownlink,
		uploadOnly:    cfg.UploadOnly,
		legProfile:    cfg.LegProfile,
		uploadWireAck: cfg.UploadWireAck,
		onClose:       cfg.OnClose,
	}
	c.downlinkReady.L = &c.readMu
	return c
}

// IsClosed reports whether Close has been called (test hook).
func (c *PacketConn) IsClosed() bool { return c.closed.Load() }

func (c *PacketConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *PacketConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *PacketConn) SetDeadline(t time.Time) error {
	c.deadlines.SetDeadline(t)
	c.downlinkReady.Broadcast()
	return nil
}

func (c *PacketConn) SetReadDeadline(t time.Time) error {
	c.deadlines.SetReadDeadline(t)
	c.downlinkReady.Broadcast()
	return nil
}

func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	c.deadlines.SetWriteDeadline(t)
	return nil
}

func (c *PacketConn) Close() error {
	c.closeOnce.Do(func() {
		if c == nil {
			return
		}
		c.closed.Store(true)
		c.downlinkReady.Broadcast()
		c.writeMu.Lock()
		c.stopUploadFlushTimerLocked()
		c.writeMu.Unlock()
		c.FlushC2SWrites()
		// Upload half: close writer then pipe reader (Extended CONNECT duplex teardown).
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
		c.downlinkReady.Broadcast()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}

// FlushC2SWrites drains coalesced upload wire without closing (docker probe / SOCKS chain parity H3Conn).
func (c *PacketConn) FlushC2SWrites() {
	if c == nil || c.closed.Load() {
		return
	}
	c.writeMu.Lock()
	wire := c.takeUploadPendingLocked()
	c.writeMu.Unlock()
	if len(wire) > 0 {
		_ = c.flushUploadWire(wire)
	}
}

func (c *PacketConn) AwaitUploadDrain(timeout time.Duration) error {
	if c == nil || c.closed.Load() {
		return nil
	}
	c.FlushC2SWrites()
	if c.uploadWireAck == nil {
		return nil
	}
	n := c.uploadWireCommitted.Load()
	if n <= 0 {
		return nil
	}
	return c.uploadWireAck.AwaitUploadWireSent(n, timeout)
}

func (c *PacketConn) noteUploadWireCommitted(n int) {
	if c != nil && n > 0 {
		c.uploadWireCommitted.Add(int64(n))
	}
}

// RunDownlinkPump starts the background body reader (explicit / tests).
func (c *PacketConn) RunDownlinkPump() {
	c.startDownlinkPump()
}

func (c *PacketConn) ensureDownlinkPump() {
	if !c.downlinkNeedsAsyncPump() {
		return
	}
	c.startDownlinkPump()
}

func (c *PacketConn) startUploadOnlyDrain() {
	if c == nil || !c.uploadOnly {
		return
	}
	c.pumpOnce.Do(func() {
		go c.runUploadOnlyDrain()
	})
}

func (c *PacketConn) runUploadOnlyDrain() {
	readBuf := c.downlinkReadScratch()
	for {
		if c.closed.Load() {
			return
		}
		nr, err := c.readResponseBodyChunk(context.Background(), readBuf)
		if nr > 0 {
			continue
		}
		if err != nil {
			return
		}
	}
}

func (c *PacketConn) startDownlinkPump() {
	if c == nil || !c.asyncDownlink {
		return
	}
	c.pumpOnce.Do(func() {
		c.pumpActive.Store(true)
		go c.runDownlinkPump()
	})
}

func (c *PacketConn) uploadInFlightLocked() bool {
	return c.uploadPending.Len() > 0 || c.uploadFlushTimer != nil
}

func (c *PacketConn) downlinkNeedsAsyncPump() bool {
	if c == nil || !c.asyncDownlink {
		return false
	}
	c.writeMu.Lock()
	inFlight := c.uploadInFlightLocked()
	c.writeMu.Unlock()
	return inFlight
}

func (c *PacketConn) downlinkReadScratch() []byte {
	if cap(c.downlinkReadBuf) < ResponseBodyBufSize {
		c.downlinkReadBuf = make([]byte, ResponseBodyBufSize)
	}
	return c.downlinkReadBuf
}

func (c *PacketConn) runDownlinkPump() {
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
func (c *PacketConn) Prime() error {
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

func (c *PacketConn) fillDownlinkQueueFromPendingLocked() (icmp bool, err error) {
	for len(c.downlinkPending) > 0 {
		if udpPayload, consumed, ok := h2c.TryConsumeDatagramCapsule512Wire(c.downlinkPending); ok {
			c.downlinkPending = c.downlinkPending[consumed:]
			if len(udpPayload) == 0 {
				return true, nil
			}
			if c.asyncDownlink && len(udpPayload) < h2MinDeliveredUDPPayload {
				continue
			}
			c.downlinkQueue = append(c.downlinkQueue, udpPayload)
			continue
		}
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
		udpPayload, ok, uerr := frame.ParseHTTPDatagramUDP(inner)
		if uerr != nil || !ok {
			continue
		}
		if len(udpPayload) == 0 {
			return true, nil
		}
		if c.asyncDownlink && len(udpPayload) < h2MinDeliveredUDPPayload {
			continue
		}
		c.downlinkQueue = append(c.downlinkQueue, udpPayload)
	}
	if len(c.downlinkPending) == 0 && cap(c.downlinkPending) > ResponseBodyBufSize*2 {
		c.downlinkPending = nil
	}
	return false, nil
}

func (c *PacketConn) tryParseOneDatagramInto(p []byte) (n int, icmp bool, err error) {
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

func (c *PacketConn) readH2DatagramIntoLocked(p []byte, ctx context.Context) (int, error) {
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
			return 0, split.ErrPortUnreachable
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

func (c *PacketConn) responseBodyReader() *bufio.Reader {
	if c.respBodyBuf == nil {
		c.respBodyBuf = bufio.NewReaderSize(c.resp.Body, ResponseBodyBufSize)
	}
	return c.respBodyBuf
}

func (c *PacketConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

func (c *PacketConn) readResponseBodyChunk(ctx context.Context, p []byte) (int, error) {
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
		// Do not Close() the whole PacketConn on read deadline — asymmetric upload leg survives.
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
	c *PacketConn
}

func (w *h2UploadWriter) Write(b []byte) (int, error) {
	c := w.c
	if c == nil || c.reqBody == nil {
		return 0, fmt.Errorf("masque h2 dataplane connect-udp: missing request body writer")
	}
	if c.deadlines.WriteTimeoutExceeded() {
		return 0, os.ErrDeadlineExceeded
	}
	return h2c.WriteAll(c.reqBody, b)
}

func (c *PacketConn) armUploadFlushTimerLocked() {
	if c.uploadFlushTimer != nil {
		return
	}
	c.uploadFlushTimerC = make(chan struct{})
	timerC := c.uploadFlushTimerC
	c.uploadFlushTimer = time.AfterFunc(h2UploadCoalesceMaxDelay, func() {
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

func (c *PacketConn) stopUploadFlushTimerLocked() {
	if c.uploadFlushTimer != nil {
		c.uploadFlushTimer.Stop()
		c.uploadFlushTimer = nil
	}
	c.uploadFlushTimerC = nil
}

func (c *PacketConn) takeUploadPendingLocked() []byte {
	c.stopUploadFlushTimerLocked()
	if c.uploadPending.Len() == 0 {
		return nil
	}
	wire := c.uploadPending.Bytes()
	c.uploadPending.Reset()
	return wire
}

func (c *PacketConn) flushUploadWire(wire []byte) error {
	if len(wire) == 0 {
		return nil
	}
	return c.writeUploadWireUnlocked(wire)
}

func (c *PacketConn) writeEmptyDatagramCapsule() error {
	if c.reqBody == nil {
		return fmt.Errorf("masque h2 dataplane connect-udp: missing request body writer")
	}
	if c.deadlines.WriteTimeoutExceeded() {
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

func (c *PacketConn) uploadWriteNeedsInterrupt() bool {
	v := c.deadlines.Write.Load()
	if v == 0 {
		return false
	}
	return time.Until(time.Unix(0, v)) <= h2UploadWriteInterruptDeadline
}

func (c *PacketConn) writeUploadWireSync(wire []byte) error {
	_, err := h2c.WriteAll(c.reqBody, wire)
	return err
}

func (c *PacketConn) writeDeadlineContext() (context.Context, context.CancelFunc) {
	if c.deadlines.WriteTimeoutExceeded() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, func() {}
	}
	if v := c.deadlines.Write.Load(); v != 0 {
		return context.WithDeadline(context.Background(), time.Unix(0, v))
	}
	return context.Background(), func() {}
}

func (c *PacketConn) uploadCoalesceThreshold() int {
	if c != nil && c.uploadOnly && c.legProfile.uploadNoCoalesceTimer() && c.bulkUpload {
		return h2UploadCoalesceThreshold
	}
	if c != nil && c.duplexActive.Load() {
		if c.bulkUpload {
			return h2UploadCoalesceBulkBytesConfigured()
		}
		return h2UploadCoalesceDuplexBytes
	}
	if c != nil && c.bulkUpload {
		return h2UploadCoalesceBulkBytesConfigured()
	}
	return h2UploadCoalesceBulkBytesConfigured()
}

func (c *PacketConn) writeUploadWireUnlocked(wire []byte) error {
	if c == nil || c.reqBody == nil || len(wire) == 0 {
		return nil
	}
	if c.deadlines.WriteTimeoutExceeded() {
		return os.ErrDeadlineExceeded
	}
	var err error
	if !c.uploadWriteNeedsInterrupt() {
		err = c.writeUploadWireSync(wire)
	} else {
		ctx, cancel := c.writeDeadlineContext()
		defer cancel()
		err = c.awaitWriteReqBody(ctx, func() error {
			return c.writeUploadWireSync(wire)
		})
	}
	if err == nil {
		c.noteUploadWireCommitted(len(wire))
	}
	return err
}

func (c *PacketConn) awaitWriteReqBody(ctx context.Context, writeFn func() error) error {
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

func (c *PacketConn) noteUploadArrivalLocked(now time.Time) {
	enterHits := h2UploadBulkEnterHits
	if c.uploadOnly && c.legProfile.uploadNoCoalesceTimer() {
		enterHits = 2 // sustained upload leg: arm 128 KiB coalesce soon after prime flush
	}
	if !c.lastUploadAt.IsZero() {
		gap := now.Sub(c.lastUploadAt)
		switch {
		case gap <= h2UploadBulkEnterGap:
			c.rapidUploadHits++
			if c.rapidUploadHits >= enterHits {
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

func (c *PacketConn) uploadFlushInteractiveLocked() bool {
	return c.duplexActive.Load() && !c.bulkUpload
}

func (c *PacketConn) flushUploadPendingForRead() error {
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

// markDuplexPeerActive arms upload coalesce when the peer leg is active (asymmetric echo).
func (c *PacketConn) markDuplexPeerActive() {
	if c == nil || c.closed.Load() {
		return
	}
	c.duplexActive.Store(true)
}

func (c *AsymmetricPacketConn) wakeDownloadPumpForUpload() {
	if pc, ok := c.download.(*PacketConn); ok && pc != nil && !pc.closed.Load() && pc.asyncDownlink {
		pc.ensureDownlinkPump()
	}
}

func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.uploadOnly {
		return 0, nil, fmt.Errorf("masque h2 dataplane connect-udp: upload-only stream")
	}
	if c.resp == nil || c.resp.Body == nil {
		return 0, nil, fmt.Errorf("masque h2 dataplane connect-udp: missing HTTP response body")
	}
	hadPayloadWrite := c.payloadWritePending.Load()
	if c.asyncDownlink {
		if hadPayloadWrite {
			c.payloadWritePending.Store(false)
		} else {
			c.ensureDownlinkPump()
		}
	} else if c.downlinkNeedsAsyncPump() {
		c.ensureDownlinkPump()
	}
	// SOCKS UDP ASSOCIATE may block in ReadFrom before any downlink; do not arm duplex coalesce yet.
	if hadPayloadWrite {
		c.duplexActive.Store(true)
		c.writeMu.Lock()
		c.bulkUpload = false
		c.rapidUploadHits = 0
		c.writesSinceRead = 0
		c.writeMu.Unlock()
		if err := c.flushUploadPendingForRead(); err != nil {
			return 0, nil, err
		}
	}
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	ctx := context.Background()
	readCancel := func() {}
	if v := c.deadlines.Read.Load(); v != 0 {
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
		if errors.Is(err, split.ErrPortUnreachable) {
			return 0, c.remoteAddr, split.NewPortUnreachableError(c.remoteAddr)
		}
		if c.deadlines.Read.Load() != 0 && (errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled)) {
			_ = c.Close()
		}
		return 0, nil, err
	}
	if n > 0 {
		c.duplexActive.Store(true)
		c.writeMu.Lock()
		c.bulkUpload = false
		c.rapidUploadHits = 0
		c.writesSinceRead = 0
		c.writeMu.Unlock()
	}
	return n, c.remoteAddr, nil
}

func (c *PacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if c.deadlines.WriteTimeoutExceeded() {
		return 0, os.ErrDeadlineExceeded
	}

	c.writeMu.Lock()
	if c.closed.Load() {
		c.writeMu.Unlock()
		return 0, net.ErrClosed
	}
	if c.deadlines.WriteTimeoutExceeded() {
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
	var encErr error
	if len(p) <= h2c.MaxUDPPayloadPerDatagramCapsule() {
		h2c.AppendDatagramCapsuleBuffer(&c.uploadPending, p)
	} else {
		encErr = h2c.AppendUDPPayloadAsDatagramCapsules(&c.uploadPending, p)
	}
	if encErr != nil {
		c.writeMu.Unlock()
		if errors.Is(encErr, io.EOF) || errors.Is(encErr, io.ErrClosedPipe) {
			return 0, encErr
		}
		if errors.Is(encErr, os.ErrDeadlineExceeded) || errors.Is(encErr, context.Canceled) {
			return 0, encErr
		}
		_ = c.Close()
		return 0, fmt.Errorf("masque h2 dataplane connect-udp encode body: %w", encErr)
	}
	if !c.duplexActive.Load() {
		c.noteUploadArrivalLocked(time.Now())
	}
	c.writesSinceRead++
	var wire []byte
	switch {
	case c.uploadOnly && ((c.legProfile.uploadImmediateFlush() && !c.duplexActive.Load()) || ThinClientConfigured()):
		wire = c.takeUploadPendingLocked()
	case c.uploadFlushInteractiveLocked():
		wire = c.takeUploadPendingLocked()
	case c.uploadPending.Len() >= c.uploadCoalesceThreshold():
		wire = c.takeUploadPendingLocked()
	case !c.duplexActive.Load() && !c.bulkUpload && c.writesSinceRead == 1:
		// First C2S datagram before ReadFrom (pipeline-1 / roundtrip @512B): never defer into ReadFrom flush.
		wire = c.takeUploadPendingLocked()
	default:
		// Bulk coalesce timer: skip on upload leg profile (sync threshold flush only).
		if !c.legProfile.uploadNoCoalesceTimer() && (c.duplexActive.Load() || c.bulkUpload) {
			c.armUploadFlushTimerLocked()
		}
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
	if c.asyncDownlink && !c.duplexActive.Load() {
		c.ensureDownlinkPump()
	}
	if len(p) > 0 {
		c.payloadWritePending.Store(true)
	}
	return len(p), nil
}

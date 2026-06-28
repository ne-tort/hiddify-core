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
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp/split"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

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
	case c.uploadOnly && c.legProfile.uploadImmediateFlush() && !c.duplexActive.Load():
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

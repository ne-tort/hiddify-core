package conn

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
)

type masqueAddr struct{ string }

func (m masqueAddr) Network() string { return frame.RequestProtocol }
func (m masqueAddr) String() string  { return m.string }

var _ net.Addr = masqueAddr{}

type http3Stream interface {
	io.ReadWriteCloser
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
	CancelRead(quic.StreamErrorCode)
}

var (
	_ http3Stream = &http3.Stream{}
	_ http3Stream = &http3.RequestStream{}
)

// H3Conn is a CONNECT-UDP net.PacketConn over HTTP/3 QUIC DATAGRAMs.
type H3Conn struct {
	str        http3Stream
	localAddr  net.Addr
	remoteAddr net.Addr

	closed    atomic.Bool
	closeOnce sync.Once
	readDone  chan struct{}

	pumpCtx    context.Context
	pumpCancel context.CancelFunc

	drainer tryDrainHTTPDatagrams
	prefetch *h3S2CPrefetchRing

	deadlineMx sync.Mutex
	readCtx           context.Context
	readCtxCancel     context.CancelFunc
	readDeadline      time.Time
	writeDeadline     time.Time

	write *h3C2SWriter
}

var _ net.PacketConn = (*H3Conn)(nil)

// NewH3Conn wraps an established HTTP/3 CONNECT-UDP request stream as net.PacketConn.
func NewH3Conn(str http3Stream, local, remote net.Addr) *H3Conn {
	return NewH3ConnWithConfig(str, local, remote, H3ConnConfig{})
}

// NewH3ConnWithConfig wraps CONNECT-UDP with per-leg tuning (asymmetric download vs upload).
func NewH3ConnWithConfig(str http3Stream, local, remote net.Addr, cfg H3ConnConfig) *H3Conn {
	c := &H3Conn{
		str:        str,
		localAddr:  local,
		remoteAddr: remote,
		readDone:   make(chan struct{}),
	}
	c.readCtx, c.readCtxCancel = context.WithCancel(context.Background())
	c.pumpCtx, c.pumpCancel = context.WithCancel(context.Background())
	if dr, ok := str.(tryDrainHTTPDatagrams); ok {
		c.drainer = dr
	}
	if cfg.LegRole.s2cPrefetchEnabled() {
		c.prefetch = newH3S2CPrefetchRing()
	}
	c.write = newH3C2SWriter(str)
	if c.drainer != nil && c.prefetch != nil {
		go c.runS2CPrefetchPump()
	}
	go func() {
		defer close(c.readDone)
		if err := frame.SkipRequestStreamCapsules(quicvarint.NewReader(str)); err != nil && !errors.Is(err, io.EOF) && !c.closed.Load() {
			log.Printf("reading from request stream failed: %v", err)
		}
		str.Close()
	}()
	return c
}

func (c *H3Conn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	if c.write != nil {
		c.write.flushPendingWriteBatch()
	}
	for {
		if c.closed.Load() {
			return 0, nil, net.ErrClosed
		}
		n, addr, err, again := c.readFromOnce(b)
		if !again {
			return n, addr, err
		}
	}
}

func (c *H3Conn) readFromOnce(b []byte) (n int, addr net.Addr, err error, again bool) {
	c.deadlineMx.Lock()
	d := c.readDeadline
	base := c.readCtx
	c.deadlineMx.Unlock()

	ctx := base
	var cancel context.CancelFunc
	if !d.IsZero() {
		if !time.Now().Before(d) {
			return 0, nil, os.ErrDeadlineExceeded, false
		}
		ctx, cancel = context.WithDeadline(base, d)
	}
	if cancel != nil {
		defer cancel()
	}

	var data []byte
	if c.prefetch != nil {
		if pref, ok := c.prefetch.take(); ok {
			data = pref
		}
	}
	if data == nil {
		data, err = c.str.ReceiveDatagram(ctx)
		if err != nil {
			if c.closed.Load() {
				return 0, nil, net.ErrClosed, false
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return 0, nil, os.ErrDeadlineExceeded, false
			}
			if errors.Is(err, context.Canceled) {
				if ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
					return 0, nil, os.ErrDeadlineExceeded, false
				}
				return 0, nil, net.ErrClosed, false
			}
			return 0, nil, err, false
		}
		c.drainTryReceiveIntoPrefetch()
	}
	payload, ok, parseErr := frame.ParseHTTPDatagramUDP(data)
	if parseErr != nil {
		quic.ReleaseMasqueDatagramReceiveBuffer(data)
		if errors.Is(parseErr, io.EOF) {
			return 0, nil, parseErr, false
		}
		return 0, nil, nil, true
	}
	if !ok {
		quic.ReleaseMasqueDatagramReceiveBuffer(data)
		return 0, nil, nil, true
	}
	if len(payload) == 0 {
		quic.ReleaseMasqueDatagramReceiveBuffer(data)
		return 0, c.remoteAddr, ErrICMPPortUnreachable, false
	}
	if err := frame.ValidateProxiedUDPPayloadLen(len(payload)); err != nil {
		quic.ReleaseMasqueDatagramReceiveBuffer(data)
		c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
		return 0, nil, err, false
	}
	n = copy(b, payload)
	quic.ReleaseMasqueDatagramReceiveBuffer(data)
	http3.WakeMasqueClientAfterDatagramReceiveFrom(c.str)
	return n, c.remoteAddr, nil, false
}

func (c *H3Conn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if err := c.write.takeErr(); err != nil {
		return 0, err
	}
	c.deadlineMx.Lock()
	wd := c.writeDeadline
	c.deadlineMx.Unlock()
	if !wd.IsZero() && !time.Now().Before(wd) {
		return 0, os.ErrDeadlineExceeded
	}
	ctx := c.pumpCtx
	var cancel context.CancelFunc
	if !wd.IsZero() {
		ctx, cancel = context.WithDeadline(c.pumpCtx, wd)
		defer cancel()
	}
	n := len(p)
	if err := c.write.writeBytes(ctx, &c.closed, p); err != nil {
		if c.closed.Load() {
			return 0, net.ErrClosed
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return 0, os.ErrDeadlineExceeded
		}
		return 0, err
	}
	return n, nil
}

func (c *H3Conn) FlushC2SWrites() {
	if c.write != nil {
		c.write.drainQueue()
	}
}

// FlushPendingC2SBatch pushes a partial NoWake batch without draining the async write queue (duplex interleave).
func (c *H3Conn) FlushPendingC2SBatch() {
	if c.write != nil {
		c.write.flushPendingWriteBatch()
	}
}

func (c *H3Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.pumpCancel()
		c.readCtxCancel()
		if c.write != nil {
			c.write.shutdown()
		}
		c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		err = c.str.Close()
		<-c.readDone
	})
	return err
}

func (c *H3Conn) LocalAddr() net.Addr  { return c.localAddr }
func (c *H3Conn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *H3Conn) SetDeadline(t time.Time) error {
	_ = c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}

func (c *H3Conn) SetReadDeadline(t time.Time) error {
	c.deadlineMx.Lock()
	c.readDeadline = t
	c.deadlineMx.Unlock()
	return nil
}

func (c *H3Conn) SetWriteDeadline(t time.Time) error {
	c.deadlineMx.Lock()
	c.writeDeadline = t
	c.deadlineMx.Unlock()
	return nil
}

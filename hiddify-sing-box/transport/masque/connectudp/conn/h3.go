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
	drain      tryDrainHTTPDatagrams
	localAddr  net.Addr
	remoteAddr net.Addr

	closed   atomic.Bool
	readDone chan struct{}

	pumpOnce       sync.Once
	pumpCtx        context.Context
	pumpCancel     context.CancelFunc
	prefetchNotify chan struct{}

	prefetchMu          sync.Mutex
	prefetchSlots       [][]byte
	prefetchHead        int
	prefetchCount       int
	prefetchCountAtomic atomic.Int32
	prefetchGate        adaptiveTryDrainGate

	deadlineMx        sync.Mutex
	readCtx           context.Context
	readCtxCancel     context.CancelFunc
	deadline          time.Time
	readDeadlineTimer *time.Timer

	write *h3C2SWriter
}

var _ net.PacketConn = (*H3Conn)(nil)

// NewH3Conn wraps an established HTTP/3 CONNECT-UDP request stream as net.PacketConn.
func NewH3Conn(str http3Stream, local, remote net.Addr) *H3Conn {
	c := &H3Conn{
		str:           str,
		localAddr:     local,
		remoteAddr:    remote,
		readDone:      make(chan struct{}),
		prefetchSlots: make([][]byte, h3PrefetchMax),
	}
	if dr, ok := str.(tryDrainHTTPDatagrams); ok {
		c.drain = dr
	}
	c.prefetchNotify = make(chan struct{}, 256)
	c.pumpCtx, c.pumpCancel = context.WithCancel(context.Background())
	c.readCtx, c.readCtxCancel = context.WithCancel(context.Background())
	c.write = newH3C2SWriter(str)
	go func() {
		defer close(c.readDone)
		if err := skipCapsules(quicvarint.NewReader(str)); err != nil && !errors.Is(err, io.EOF) && !c.closed.Load() {
			log.Printf("reading from request stream failed: %v", err)
		}
		str.Close()
	}()
	return c
}

func (c *H3Conn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	c.startDatagramPump()
	expiredPrefetchDrops := 0
start:
	c.deadlineMx.Lock()
	ctx := c.readCtx
	c.deadlineMx.Unlock()

	var data []byte
	fromPrefetch := false
	hasBufferedPrefetch := false
	if raw, ok, hasMore := c.takePrefetched(); ok {
		data = raw
		fromPrefetch = true
		hasBufferedPrefetch = hasMore
	} else {
		c.extendPrefetchFromTry(true)
		if raw, ok, hasMore := c.takePrefetched(); ok {
			data = raw
			fromPrefetch = true
			hasBufferedPrefetch = hasMore
		} else {
			data, err = c.waitPrefetched(ctx)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					return 0, nil, err
				}
				c.deadlineMx.Lock()
				restart := time.Now().Before(c.deadline)
				c.deadlineMx.Unlock()
				if restart {
					goto start
				}
				return 0, nil, os.ErrDeadlineExceeded
			}
		}
	}
	payload, ok, parseErr := frame.ParseHTTPDatagramUDP(data)
	if parseErr != nil {
		goto dropAndContinue
	}
	if !ok {
		goto dropAndContinue
	}
	if len(payload) == 0 {
		return 0, c.remoteAddr, ErrICMPPortUnreachable
	}
	n = copy(b, payload)
	if !fromPrefetch || !hasBufferedPrefetch {
		c.extendPrefetchFromTry(true)
	}
	http3.WakeMasqueClientAfterDatagramReceiveFrom(c.str)
	return n, c.remoteAddr, nil

dropAndContinue:
	c.deadlineMx.Lock()
	deadlineExceeded := !c.deadline.IsZero() && !time.Now().Before(c.deadline)
	c.deadlineMx.Unlock()
	if deadlineExceeded {
		expiredPrefetchDrops++
		if expiredPrefetchDrops >= h3PrefetchExpiredDropBudget {
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
	if !fromPrefetch || !hasBufferedPrefetch {
		c.extendPrefetchFromTry(true)
	}
	goto start
}

func (c *H3Conn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.startDatagramPump()
	if err := c.write.takeErr(); err != nil {
		return 0, err
	}
	n := len(p)
	if err := c.write.enqueue(c.pumpCtx, p); err != nil {
		return 0, err
	}
	return n, nil
}

func (c *H3Conn) FlushC2SWrites() {
	if c.write != nil {
		c.write.drainQueue()
	}
}

func (c *H3Conn) Close() error {
	c.closed.Store(true)
	c.pumpCancel()
	c.signalPrefetchReady()
	c.FlushC2SWrites()
	c.write.close(c.pumpCtx)
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	err := c.str.Close()
	<-c.readDone
	c.readCtxCancel()
	c.deadlineMx.Lock()
	if c.readDeadlineTimer != nil {
		c.readDeadlineTimer.Stop()
	}
	c.deadlineMx.Unlock()
	return err
}

func (c *H3Conn) LocalAddr() net.Addr  { return c.localAddr }
func (c *H3Conn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *H3Conn) SetDeadline(t time.Time) error {
	_ = c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}

func (c *H3Conn) SetReadDeadline(t time.Time) error {
	var cancelOutside context.CancelFunc

	c.deadlineMx.Lock()
	oldDeadline := c.deadline
	c.deadline = t
	now := time.Now()
	if t.IsZero() {
		if c.readDeadlineTimer != nil && !c.readDeadlineTimer.Stop() {
			<-c.readDeadlineTimer.C
		}
		c.deadlineMx.Unlock()
		return nil
	}
	if !t.After(now) {
		cancelOutside = c.readCtxCancel
		c.deadlineMx.Unlock()
		cancelOutside()
		return nil
	}
	deadline := t.Sub(now)
	if c.readDeadlineTimer != nil {
		if now.Before(oldDeadline) {
			cancelOutside = c.readCtxCancel
			c.readCtx, c.readCtxCancel = context.WithCancel(context.Background())
		}
		c.readDeadlineTimer.Reset(deadline)
	} else {
		c.readDeadlineTimer = time.AfterFunc(deadline, func() {
			c.deadlineMx.Lock()
			shouldCancel := !c.deadline.IsZero() && c.deadline.Before(time.Now())
			cancelFn := c.readCtxCancel
			c.deadlineMx.Unlock()
			if shouldCancel && cancelFn != nil {
				cancelFn()
			}
		})
	}
	c.deadlineMx.Unlock()
	if cancelOutside != nil {
		cancelOutside()
	}
	return nil
}

func (c *H3Conn) SetWriteDeadline(time.Time) error {
	return nil
}

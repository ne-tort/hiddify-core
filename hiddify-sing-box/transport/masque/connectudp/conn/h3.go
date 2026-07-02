package conn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/sagernet/sing-box/transport/masque/connectudp/diag"
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

// tryDrainHTTPDatagrams is quic-go HTTP/3 non-blocking datagram dequeue (masque-go conn shape).
type tryDrainHTTPDatagrams interface {
	TryReceiveDatagram() ([]byte, bool)
}

var (
	_ http3Stream = &http3.Stream{}
	_ http3Stream = &http3.RequestStream{}
)

// H3Conn is a CONNECT-UDP net.PacketConn over HTTP/3 QUIC DATAGRAMs (masque-go conn.go ReadFrom/WriteTo shape).
type H3Conn struct {
	str        http3Stream
	localAddr  net.Addr
	remoteAddr net.Addr
	legRole    H3LegRole

	closed   atomic.Bool
	closeOnce sync.Once
	readDone chan struct{}

	write *h3C2SWriter

	deadlineMx        sync.Mutex
	readCtxStore      atomic.Pointer[context.Context]
	readCtxCancel     context.CancelFunc
	deadline          time.Time
	readDeadlineTimer *time.Timer
}

var _ net.PacketConn = (*H3Conn)(nil)

// NewH3Conn wraps an established HTTP/3 CONNECT-UDP request stream as net.PacketConn.
func NewH3Conn(str http3Stream, local, remote net.Addr) *H3Conn {
	return NewH3ConnWithConfig(str, local, remote, H3ConnConfig{})
}

// NewH3ConnWithConfig wraps CONNECT-UDP (config retained for asymmetric leg tagging).
func NewH3ConnWithConfig(str http3Stream, local, remote net.Addr, cfg H3ConnConfig) *H3Conn {
	c := &H3Conn{
		str:        str,
		localAddr:  local,
		remoteAddr: remote,
		legRole:    cfg.LegRole,
		readDone:   make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.readCtxCancel = cancel
	c.readCtxStore.Store(&ctx)
	c.write = newH3C2SWriter(str, 0)
	if cfg.LegRole == H3LegDownload {
		armH3AsymmetricDownloadLeg(str)
	}
	go func() {
		defer close(c.readDone)
		if err := frame.SkipRequestStreamCapsules(quicvarint.NewReader(str)); err != nil && !errors.Is(err, io.EOF) && !c.closed.Load() {
			diag.Logf("reading from request stream failed: %v", err)
		}
		// Asymmetric download leg stays open for ReceiveDatagram until Close (upload leg parity).
		// Bidi closes after skip — single stream, masque-go conn.go shape.
		if cfg.LegRole == H3LegBidi {
			str.Close()
		}
	}()
	return c
}

func (c *H3Conn) loadReadCtx() context.Context {
	if p := c.readCtxStore.Load(); p != nil {
		return *p
	}
	return context.Background()
}

func (c *H3Conn) resetReadCtxLocked() {
	if c.readCtxCancel != nil {
		c.readCtxCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.readCtxCancel = cancel
	c.readCtxStore.Store(&ctx)
}

func (c *H3Conn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
start:
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	if drainer, ok := c.str.(tryDrainHTTPDatagrams); ok {
		for {
			data, ok := drainer.TryReceiveDatagram()
			if !ok {
				break
			}
			if n, addr, err, done := c.deliverReadFrom(b, data); done {
				return n, addr, err
			}
		}
	}
	ctx := c.loadReadCtx()
	data, err := c.str.ReceiveDatagram(ctx)
	if err != nil {
		if c.closed.Load() {
			return 0, nil, net.ErrClosed
		}
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
	n, addr, err, done := c.deliverReadFrom(b, data)
	if !done {
		goto start
	}
	return n, addr, err
}

func (c *H3Conn) deliverReadFrom(b, data []byte) (n int, addr net.Addr, err error, done bool) {
	defer quic.ReleaseMasqueDatagramReceiveBuffer(data)
	payload, ok, parseErr := frame.ParseHTTPDatagramUDPFast(data)
	if parseErr != nil {
		if errors.Is(parseErr, io.EOF) {
			return 0, nil, parseErr, true
		}
		return 0, nil, fmt.Errorf("masque connect-udp: malformed datagram: %w", parseErr), true
	}
	if !ok {
		return 0, nil, nil, false
	}
	if len(payload) == 0 {
		return 0, c.remoteAddr, ErrICMPPortUnreachable, true
	}
	if len(payload) > frame.MaxProxiedUDPPayloadBytes {
		c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
		return 0, nil, frame.ErrProxiedUDPPayloadTooLarge, true
	}
	return copy(b, payload), c.remoteAddr, nil, true
}

// WriteTo sends a UDP datagram to the target (sync SendDatagram; masque-go conn.go).
func (c *H3Conn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if err := c.write.writeBytes(context.Background(), &c.closed, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *H3Conn) FlushC2SWrites() {
	c.flushDatagramSend()
}

func (c *H3Conn) FlushPendingC2SBatch() {
	c.flushDatagramSend()
}

func (c *H3Conn) flushDatagramSend() {
	if c == nil {
		return
	}
	if c.write != nil {
		c.write.flushC2SDatagramWake()
		return
	}
	if c.str == nil {
		return
	}
	if f, ok := c.str.(interface{ FlushProxiedIPDatagramSend() }); ok {
		f.FlushProxiedIPDatagramSend()
	}
}

func (c *H3Conn) AwaitUploadDrain(timeout time.Duration) error {
	if c == nil || c.closed.Load() {
		return nil
	}
	if timeout <= 0 {
		timeout = 200 * time.Millisecond
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c.flushDatagramSend()
		if b, ok := c.str.(interface{ DatagramSendBacklog() int }); ok && b.DatagramSendBacklog() == 0 {
			return nil
		}
		runtime.Gosched()
	}
	c.flushDatagramSend()
	if b, ok := c.str.(interface{ DatagramSendBacklog() int }); ok && b.DatagramSendBacklog() > 0 {
		return fmt.Errorf("masque h3: upload drain timeout with backlog=%d", b.DatagramSendBacklog())
	}
	return nil
}

func (c *H3Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		if c.legRole == H3LegDownload {
			disarmH3AsymmetricDownloadLeg(c.str)
		}
		if c.write != nil {
			c.write.shutdown()
		}
		c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		err = c.str.Close()
		<-c.readDone
		c.readCtxCancel()
		c.deadlineMx.Lock()
		if c.readDeadlineTimer != nil {
			c.readDeadlineTimer.Stop()
		}
		c.deadlineMx.Unlock()
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
	defer c.deadlineMx.Unlock()
	oldDeadline := c.deadline
	c.deadline = t
	now := time.Now()
	if t.IsZero() {
		if c.readDeadlineTimer != nil && !c.readDeadlineTimer.Stop() {
			<-c.readDeadlineTimer.C
		}
		c.resetReadCtxLocked()
		return nil
	}
	if !t.After(now) {
		c.readCtxCancel()
		return nil
	}
	deadline := t.Sub(now)
	if c.readDeadlineTimer != nil {
		if now.Before(oldDeadline) {
			c.resetReadCtxLocked()
		}
		c.readDeadlineTimer.Reset(deadline)
	} else {
		c.readDeadlineTimer = time.AfterFunc(deadline, func() {
			c.deadlineMx.Lock()
			defer c.deadlineMx.Unlock()
			if !c.deadline.IsZero() && c.deadline.Before(time.Now()) {
				c.readCtxCancel()
			}
		})
	}
	return nil
}

func (c *H3Conn) SetWriteDeadline(time.Time) error {
	return nil
}

package masque

// TUN-order synth via route.ConnectionManager + lazy handshake inbound (W-IP-TUN IP-TUN-PR6).
// Exported for connectip/inttest without masque ↔ server import cycle.

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/route"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// cmLazyHandshakeConn defers inbound I/O until CM reports outbound dial success (gLazyConn analog).
type cmLazyHandshakeConn struct {
	relayConn     net.Conn
	mu            sync.Mutex
	handshakeDone bool
	handshakeErr  error
	signal        chan struct{}
}

func newCMLazyHandshakeConn() (*cmLazyHandshakeConn, net.Conn) {
	relay, app := net.Pipe()
	return &cmLazyHandshakeConn{relayConn: relay, signal: make(chan struct{})}, app
}

func (c *cmLazyHandshakeConn) HandshakeContext(ctx context.Context) error {
	c.mu.Lock()
	if c.handshakeDone {
		err := c.handshakeErr
		c.mu.Unlock()
		return err
	}
	c.mu.Unlock()
	select {
	case <-c.signal:
		c.mu.Lock()
		if !c.handshakeDone {
			c.handshakeDone = true
		}
		err := c.handshakeErr
		c.mu.Unlock()
		return err
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (c *cmLazyHandshakeConn) HandshakeSuccess() error {
	c.signalSuccess()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.handshakeDone {
		c.handshakeDone = true
	}
	return c.handshakeErr
}

func (c *cmLazyHandshakeConn) HandshakeFailure(err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handshakeDone {
		return io.ErrClosedPipe
	}
	c.handshakeErr = err
	c.handshakeDone = true
	close(c.signal)
	_ = c.relayConn.Close()
	return err
}

func (c *cmLazyHandshakeConn) NeedHandshakeForRead() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.handshakeDone
}

func (c *cmLazyHandshakeConn) Read(b []byte) (int, error) {
	if err := c.HandshakeContext(context.Background()); err != nil {
		return 0, err
	}
	return c.relayConn.Read(b)
}

func (c *cmLazyHandshakeConn) Write(b []byte) (int, error) {
	if err := c.HandshakeContext(context.Background()); err != nil {
		return 0, err
	}
	return c.relayConn.Write(b)
}

func (c *cmLazyHandshakeConn) Close() error {
	c.mu.Lock()
	if !c.handshakeDone {
		c.handshakeErr = net.ErrClosed
		c.handshakeDone = true
		close(c.signal)
	}
	c.mu.Unlock()
	return c.relayConn.Close()
}

func (c *cmLazyHandshakeConn) LocalAddr() net.Addr  { return c.relayConn.LocalAddr() }
func (c *cmLazyHandshakeConn) RemoteAddr() net.Addr { return c.relayConn.RemoteAddr() }

func (c *cmLazyHandshakeConn) SetDeadline(t time.Time) error {
	if err := c.HandshakeContext(context.Background()); err != nil {
		return err
	}
	return c.relayConn.SetDeadline(t)
}

func (c *cmLazyHandshakeConn) SetReadDeadline(t time.Time) error {
	if err := c.HandshakeContext(context.Background()); err != nil {
		return err
	}
	return c.relayConn.SetReadDeadline(t)
}

func (c *cmLazyHandshakeConn) SetWriteDeadline(t time.Time) error {
	if err := c.HandshakeContext(context.Background()); err != nil {
		return err
	}
	return c.relayConn.SetWriteDeadline(t)
}

func (c *cmLazyHandshakeConn) signalSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handshakeDone {
		return
	}
	c.handshakeErr = nil
	close(c.signal)
}

// ConnectIPTunCMRouter routes synthetic TUN TCP flows through ConnectionManager.
type ConnectIPTunCMRouter struct {
	cm     *route.ConnectionManager
	router *directMasqueRouter
	active atomic.Int32
}

// NewConnectIPTunCMRouter wires masque session outbound into route.ConnectionManager.
func NewConnectIPTunCMRouter(t testing.TB, session ClientSession) *ConnectIPTunCMRouter {
	t.Helper()
	out := &masqueSessionOutbound{
		Adapter: outbound.NewAdapter(constant.TypeMasque, "masque-out", []string{N.NetworkTCP, N.NetworkUDP}, nil),
		sess:    session,
	}
	cm := route.NewConnectionManager(log.StdLogger())
	t.Cleanup(func() { _ = cm.Close() })
	return &ConnectIPTunCMRouter{
		cm:     cm,
		router: &directMasqueRouter{cm: cm, dialer: out},
	}
}

// ActiveRelayCount returns open CM synth relays (test hook).
func (r *ConnectIPTunCMRouter) ActiveRelayCount() int {
	if r == nil {
		return 0
	}
	return int(r.active.Load())
}

// RouteTunTCP runs fn on the app-side conn while CM relays through connect_ip outbound.
func (r *ConnectIPTunCMRouter) RouteTunTCP(ctx context.Context, dest M.Socksaddr, fn func(net.Conn)) error {
	lazy, app := newCMLazyHandshakeConn()
	inbound := wrapCMLazyForCM(lazy)
	done := make(chan struct{})
	var routeErr error
	r.active.Add(1)
	go r.router.RouteConnectionEx(ctx, inbound, adapter.InboundContext{
		Inbound:     "tun-in",
		InboundType: constant.TypeTun,
		Destination: dest,
	}, N.OnceClose(func(err error) {
		r.active.Add(-1)
		if err != nil && !errorsIsClosed(err) {
			routeErr = err
		}
		close(done)
	}))
	go func() {
		<-ctx.Done()
		_ = inbound.Close()
		_ = app.Close()
	}()
	fn(app)
	_ = app.Close()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return routeErr
}

func errorsIsClosed(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(err.Error(), "closed pipe")
}

// cmLazyPostDialReporter signals lazy inbound after CM dials outbound (ConnHandshakeSuccess hook).
type cmLazyPostDialReporter struct {
	*cmLazyHandshakeConn
}

func (c *cmLazyPostDialReporter) ConnHandshakeSuccess(net.Conn) error {
	c.signalSuccess()
	return nil
}

func wrapCMLazyForCM(lazy *cmLazyHandshakeConn) net.Conn {
	return &cmLazyPostDialReporter{cmLazyHandshakeConn: lazy}
}

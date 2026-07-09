package session

import (
	"context"
	"io"
	"net"
	"sync"

	C "github.com/sagernet/sing-box/constant"
)

// connectStreamPeerBidiBudget caps live + opening CONNECT-stream bidi streams per QUIC session.
//
// quic-go http3 RoundTrip blocks in OpenStreamSync when peer MAX_STREAMS is exhausted; excess
// dials then fail after the handshake ctx (~30s) as "connect roundtrip: context canceled".
// This semaphore queues new dials before RoundTrip so slots recycle on tunnel Close.
const connectStreamPeerBidiBudget = 48

// ConnectStreamBudget bounds total CONNECT-stream QUIC bidi slots (opening + active tunnels).
type ConnectStreamBudget struct {
	slots chan struct{}
}

// NewConnectStreamBudget builds a stream-budget limiter with n slots.
func NewConnectStreamBudget(n int) *ConnectStreamBudget {
	if n <= 0 {
		n = connectStreamPeerBidiBudget
	}
	return &ConnectStreamBudget{slots: make(chan struct{}, n)}
}

// Acquire waits for a stream slot or returns when ctx is done.
func (b *ConnectStreamBudget) Acquire(ctx context.Context) error {
	if b == nil || b.slots == nil {
		return nil
	}
	select {
	case b.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

// Release returns a slot from Acquire or from AttachConnectStreamBudgetRelease on Close.
func (b *ConnectStreamBudget) Release() {
	if b == nil || b.slots == nil {
		return
	}
	select {
	case <-b.slots:
	default:
	}
}

// AttachConnectStreamBudgetRelease transfers one Acquire slot to conn until Close.
func AttachConnectStreamBudgetRelease(c net.Conn, b *ConnectStreamBudget) net.Conn {
	if c == nil || b == nil {
		return c
	}
	return &connectStreamBudgetConn{Conn: c, budget: b}
}

type connectStreamBudgetConn struct {
	net.Conn
	budget      *ConnectStreamBudget
	releaseOnce sync.Once
}

func (c *connectStreamBudgetConn) Close() error {
	err := c.Conn.Close()
	c.releaseOnce.Do(func() {
		if c.budget != nil {
			c.budget.Release()
		}
	})
	return err
}

func (c *connectStreamBudgetConn) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := c.Conn.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(c.Conn, r)
}

func (c *connectStreamBudgetConn) WriteTo(w io.Writer) (int64, error) {
	if wt, ok := c.Conn.(io.WriterTo); ok {
		return wt.WriteTo(w)
	}
	return io.Copy(w, c.Conn)
}

func (c *connectStreamBudgetConn) RouteConnectionCopyWriterTo() {}

func (c *connectStreamBudgetConn) RouteConnectionCopyReaderFrom() {}

func (c *connectStreamBudgetConn) MarkConnectionCopyDuplex() {
	if d, ok := c.Conn.(C.RouteConnectionCopyDuplex); ok {
		d.MarkConnectionCopyDuplex()
	}
}

func (c *connectStreamBudgetConn) ConnectStreamCloseDone() <-chan struct{} {
	if d, ok := c.Conn.(interface{ ConnectStreamCloseDone() <-chan struct{} }); ok {
		return d.ConnectStreamCloseDone()
	}
	done := make(chan struct{})
	close(done)
	return done
}

var (
	_ io.WriterTo                   = (*connectStreamBudgetConn)(nil)
	_ io.ReaderFrom                 = (*connectStreamBudgetConn)(nil)
	_ C.RouteConnectionCopyWriterTo = (*connectStreamBudgetConn)(nil)
	_ C.RouteConnectionCopyReaderFrom = (*connectStreamBudgetConn)(nil)
	_ C.RouteConnectionCopyDuplex   = (*connectStreamBudgetConn)(nil)
)

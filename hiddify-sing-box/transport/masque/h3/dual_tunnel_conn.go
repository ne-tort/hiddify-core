package h3

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	C "github.com/sagernet/sing-box/constant"
)

// DualTunnelConn composites separate download and upload CONNECT-stream legs (P2).
// Wire: two RFC 9114 CONNECT requests on one QUIC connection; route sees one net.Conn.
type DualTunnelConn struct {
	download net.Conn
	upload   net.Conn
	ctx      context.Context
	cancel   context.CancelFunc
	local    net.Addr
	remote   net.Addr
	closeMu  sync.Mutex
	closed   bool
}

// DualTunnelConnParams configures a P2 composite tunnel.
type DualTunnelConnParams struct {
	Download net.Conn
	Upload   net.Conn
	Ctx      context.Context
	Local    net.Addr
	Remote   net.Addr
}

// NewDualTunnelConn builds a composite net.Conn over download + upload CONNECT legs.
func NewDualTunnelConn(p DualTunnelConnParams) *DualTunnelConn {
	if p.Download == nil || p.Upload == nil {
		return nil
	}
	ctx := p.Ctx
	var cancel context.CancelFunc
	if ctx == nil {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	local, remote := p.Local, p.Remote
	if local == nil {
		local = p.Download.LocalAddr()
	}
	if remote == nil {
		remote = p.Download.RemoteAddr()
	}
	return &DualTunnelConn{
		download: p.Download,
		upload:   p.Upload,
		ctx:      ctx,
		cancel:   cancel,
		local:    local,
		remote:   remote,
	}
}

func (c *DualTunnelConn) legErr(err error) error {
	if err == nil || errors.Is(err, io.EOF) {
		return err
	}
	return errors.Join(ErrTunnelConnFailed, err)
}

func (c *DualTunnelConn) Read(p []byte) (int, error) {
	if c == nil || c.download == nil {
		return 0, io.EOF
	}
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.download.Read(p)
	return n, c.legErr(err)
}

func (c *DualTunnelConn) Write(p []byte) (int, error) {
	if c == nil || c.upload == nil {
		return 0, io.ErrClosedPipe
	}
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.upload.Write(p)
	return n, c.legErr(err)
}

func (c *DualTunnelConn) ReadFrom(r io.Reader) (int64, error) {
	if c == nil || c.upload == nil {
		return 0, io.ErrClosedPipe
	}
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	if rf, ok := c.upload.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(r)
		if err != nil && !errors.Is(err, io.EOF) {
			return n, c.legErr(err)
		}
		return n, err
	}
	n, err := io.Copy(c.upload, r)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, c.legErr(err)
	}
	return n, err
}

func (c *DualTunnelConn) WriteTo(w io.Writer) (int64, error) {
	if c == nil || c.download == nil {
		return 0, io.EOF
	}
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	if wt, ok := c.download.(io.WriterTo); ok {
		n, err := wt.WriteTo(w)
		if err != nil && !errors.Is(err, io.EOF) {
			return n, c.legErr(err)
		}
		return n, err
	}
	buf := make([]byte, connectStreamBufLen)
	n, err := io.CopyBuffer(w, c.download, buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, c.legErr(err)
	}
	return n, err
}

func (c *DualTunnelConn) Close() error {
	if c == nil {
		return nil
	}
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.cancel()
	var err error
	if c.upload != nil {
		err = errors.Join(err, c.upload.Close())
	}
	if c.download != nil {
		err = errors.Join(err, c.download.Close())
	}
	return err
}

func (c *DualTunnelConn) CloseWrite() error {
	if c == nil || c.upload == nil {
		return nil
	}
	if cw, ok := c.upload.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *DualTunnelConn) LocalAddr() net.Addr  { return c.local }
func (c *DualTunnelConn) RemoteAddr() net.Addr { return c.remote }

func (c *DualTunnelConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}

func (c *DualTunnelConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.download == nil {
		return ErrDeadlineUnsupported
	}
	if d, ok := c.download.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return ErrDeadlineUnsupported
}

func (c *DualTunnelConn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.upload == nil {
		return ErrDeadlineUnsupported
	}
	if d, ok := c.upload.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(t)
	}
	return ErrDeadlineUnsupported
}

func (c *DualTunnelConn) ConnectStreamCloseDone() <-chan struct{} {
	if c == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	if c.download != nil {
		if lifecycle, ok := c.download.(interface{ ConnectStreamCloseDone() <-chan struct{} }); ok {
			return lifecycle.ConnectStreamCloseDone()
		}
	}
	done := make(chan struct{})
	close(done)
	return done
}

func (c *DualTunnelConn) TunnelPolicySnapshot() TunnelPolicySnapshot {
	if c == nil {
		return TunnelPolicySnapshot{}
	}
	return TunnelPolicySnapshot{
		RouteBidiDuplex: false,
		UsesH3Stream:    true,
	}
}

func (*DualTunnelConn) RouteConnectionCopyWriterTo()   {}
func (*DualTunnelConn) RouteConnectionCopyReaderFrom() {}

var (
	_ TunnelFacade                    = (*DualTunnelConn)(nil)
	_ C.RouteConnectionCopyWriterTo   = (*DualTunnelConn)(nil)
	_ C.RouteConnectionCopyReaderFrom = (*DualTunnelConn)(nil)
)

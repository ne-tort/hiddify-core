package h3

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	C "github.com/sagernet/sing-box/constant"
)

// ThinTunnelConn is an Invisv-shaped H3 CONNECT tunnel: direct stream I/O without MS3 scheduler.
type ThinTunnelConn struct {
	h3     h3ConnectStream
	ctx    context.Context
	cancel context.CancelFunc
	local  net.Addr
	remote net.Addr

	readMu  sync.Mutex
	writeMu sync.Mutex
	readDL  time.Time
	writeDL time.Time

	uploadTrafficStarted int32
	requestCancel        context.CancelCauseFunc
	requestCancelOnce    sync.Once
	closeFullOnce        sync.Once
	closeDoneOnce        sync.Once
	closeDone            chan struct{}
}

// ThinTunnelConnParams configures a thin H3 CONNECT tunnel.
type ThinTunnelConnParams struct {
	H3Stream h3ConnectStream
	Ctx      context.Context
	Local    net.Addr
	Remote   net.Addr
}

// NewThinTunnelConn builds a thin tunneled net.Conn over one HTTP/3 CONNECT stream.
func NewThinTunnelConn(p ThinTunnelConnParams) *ThinTunnelConn {
	ctx := p.Ctx
	var cancel context.CancelFunc
	if ctx == nil {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	return &ThinTunnelConn{
		h3:        p.H3Stream,
		ctx:       ctx,
		cancel:    cancel,
		local:     p.Local,
		remote:    p.Remote,
		closeDone: make(chan struct{}),
	}
}

func (c *ThinTunnelConn) ConnectStreamCloseDone() <-chan struct{} {
	if c == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	return c.closeDone
}

func (c *ThinTunnelConn) TunnelPolicySnapshot() TunnelPolicySnapshot {
	return TunnelPolicySnapshot{
		Mode:         ConnectStreamModeThinBidi,
		UsesH3Stream: c != nil && c.h3 != nil,
	}
}

func (c *ThinTunnelConn) SetConnectStreamRequestCancel(cancel context.CancelCauseFunc) {
	if c != nil {
		c.requestCancel = cancel
	}
}

func (c *ThinTunnelConn) LocalAddr() net.Addr  { return c.local }
func (c *ThinTunnelConn) RemoteAddr() net.Addr { return c.remote }

func (c *ThinTunnelConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *ThinTunnelConn) SetReadDeadline(t time.Time) error {
	if c == nil {
		return ErrDeadlineUnsupported
	}
	c.readMu.Lock()
	c.readDL = t
	c.readMu.Unlock()
	return nil
}

func (c *ThinTunnelConn) SetWriteDeadline(t time.Time) error {
	if c == nil {
		return ErrDeadlineUnsupported
	}
	c.writeMu.Lock()
	c.writeDL = t
	c.writeMu.Unlock()
	return nil
}

func (c *ThinTunnelConn) Read(p []byte) (int, error) {
	if c == nil || c.h3 == nil {
		return 0, io.EOF
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if !c.readDL.IsZero() {
		_ = c.h3.SetReadDeadline(c.readDL)
	} else {
		_ = c.h3.SetReadDeadline(time.Time{})
	}
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.h3.Read(p)
	if err != nil {
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	return n, err
}

func (c *ThinTunnelConn) Write(p []byte) (int, error) {
	if c == nil || c.h3 == nil {
		return 0, io.ErrClosedPipe
	}
	if len(p) > 0 {
		atomic.StoreInt32(&c.uploadTrafficStarted, 1)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if !c.writeDL.IsZero() {
		_ = c.h3.SetWriteDeadline(c.writeDL)
	}
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.h3.Write(p)
	if err != nil {
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	return n, err
}

func (c *ThinTunnelConn) ReadFrom(r io.Reader) (int64, error) {
	if c == nil || c.h3 == nil {
		return 0, io.ErrClosedPipe
	}
	n, err := io.Copy(c, r)
	if err != nil && !errors.Is(err, io.EOF) {
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	return n, err
}

func (c *ThinTunnelConn) WriteTo(w io.Writer) (int64, error) {
	if c == nil || c.h3 == nil {
		return 0, io.EOF
	}
	c.readMu.Lock()
	if !c.readDL.IsZero() {
		_ = c.h3.SetReadDeadline(c.readDL)
	} else {
		_ = c.h3.SetReadDeadline(time.Time{})
	}
	c.readMu.Unlock()
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	if wt, ok := c.h3.(io.WriterTo); ok {
		n, werr := wt.WriteTo(w)
		if werr != nil {
			werr = errors.Join(ErrTunnelConnFailed, werr)
		}
		return n, werr
	}
	n, err := io.Copy(w, c.h3)
	if err != nil && !errors.Is(err, io.EOF) {
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	return n, err
}

func (c *ThinTunnelConn) CloseWrite() error {
	if c == nil || c.h3 == nil {
		return nil
	}
	return c.h3.Close()
}

func (c *ThinTunnelConn) Close() error {
	if c == nil {
		return nil
	}
	var err error
	c.closeFullOnce.Do(func() {
		err = c.closeFull()
	})
	return err
}

func (c *ThinTunnelConn) closeFull() error {
	c.cancel()
	c.requestCancelOnce.Do(func() {
		if c.requestCancel != nil {
			c.requestCancel(context.Canceled)
		}
	})
	var err error
	if c.h3 != nil {
		h3 := c.h3
		cancelCode := quic.StreamErrorCode(http3.ErrCodeRequestCanceled)
		if atomic.LoadInt32(&c.uploadTrafficStarted) == 0 {
			err = h3.Close()
			c.markCloseDone()
		} else {
			closeDone := make(chan error, 1)
			go func() {
				closeDone <- h3.Close()
				c.markCloseDone()
			}()
			select {
			case closeErr := <-closeDone:
				if closeErr != nil {
					err = errors.Join(err, closeErr)
				}
			case <-time.After(connectStreamDownloadCloseTimeout):
				h3.CancelRead(cancelCode)
				c.markCloseDone()
			}
		}
	} else {
		c.markCloseDone()
	}
	return err
}

func (c *ThinTunnelConn) markCloseDone() {
	if c == nil {
		return
	}
	c.closeDoneOnce.Do(func() {
		if c.closeDone != nil {
			close(c.closeDone)
		}
	})
}

func (c *ThinTunnelConn) MarkConnectionCopyDuplex() {}

func (c *ThinTunnelConn) RouteConnectionCopyWriterTo()   {}
func (c *ThinTunnelConn) RouteConnectionCopyReaderFrom() {}

var (
	_ TunnelFacade                    = (*ThinTunnelConn)(nil)
	_ C.RouteConnectionCopyWriterTo   = (*ThinTunnelConn)(nil)
	_ C.RouteConnectionCopyReaderFrom = (*ThinTunnelConn)(nil)
	_ C.RouteConnectionCopyDuplex     = (*ThinTunnelConn)(nil)
)

package stream

import (
	"errors"
	"io"
	"net"
	"time"

	C "github.com/sagernet/sing-box/constant"
)

// TunnelConn maps tunnel errors to TCPConnectStreamFailed for template TCP dials.
type TunnelConn struct {
	Inner net.Conn
}

// NewTunnelConn wraps inner with CONNECT-stream error mapping.
func NewTunnelConn(inner net.Conn) *TunnelConn {
	return &TunnelConn{Inner: inner}
}

func (c *TunnelConn) Read(p []byte) (int, error) {
	n, err := c.Inner.Read(p)
	if err == nil || errors.Is(err, io.EOF) {
		return n, err
	}
	if errors.Is(err, io.ErrClosedPipe) {
		return n, err
	}
	return n, JoinTunnelReadErr(err)
}

func (c *TunnelConn) Write(p []byte) (int, error) {
	n, err := c.Inner.Write(p)
	if err == nil || errors.Is(err, io.EOF) {
		return n, err
	}
	if errors.Is(err, io.ErrClosedPipe) {
		return n, err
	}
	return n, JoinTunnelWriteErr(err)
}

func (c *TunnelConn) Close() error { return c.Inner.Close() }

func (c *TunnelConn) CloseWrite() error {
	if cw, ok := c.Inner.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
func (c *TunnelConn) LocalAddr() net.Addr                { return c.Inner.LocalAddr() }
func (c *TunnelConn) RemoteAddr() net.Addr               { return c.Inner.RemoteAddr() }
func (c *TunnelConn) SetDeadline(t time.Time) error      { return c.Inner.SetDeadline(t) }
func (c *TunnelConn) SetReadDeadline(t time.Time) error  { return c.Inner.SetReadDeadline(t) }
func (c *TunnelConn) SetWriteDeadline(t time.Time) error { return c.Inner.SetWriteDeadline(t) }

func (c *TunnelConn) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := c.Inner.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(r)
		if err != nil && !errors.Is(err, io.EOF) {
			return n, JoinTunnelWriteErr(err)
		}
		return n, err
	}
	n, err := io.Copy(c, r)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, JoinTunnelWriteErr(err)
	}
	return n, err
}

func (c *TunnelConn) WriteTo(w io.Writer) (int64, error) {
	if wt, ok := c.Inner.(io.WriterTo); ok {
		n, err := wt.WriteTo(w)
		if err != nil && !errors.Is(err, io.EOF) {
			return n, JoinTunnelReadErr(err)
		}
		return n, err
	}
	n, err := io.Copy(w, c.Inner)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, JoinTunnelReadErr(err)
	}
	return n, err
}

// RouteConnectionCopyWriterTo opts into route io.WriterTo bulk download when the inner conn supports it.
func (c *TunnelConn) RouteConnectionCopyWriterTo() {}

// RouteConnectionCopyReaderFrom opts into route io.ReaderFrom bulk upload when the inner conn supports it.
func (c *TunnelConn) RouteConnectionCopyReaderFrom() {}

var (
	_ C.RouteConnectionCopyWriterTo   = (*TunnelConn)(nil)
	_ C.RouteConnectionCopyReaderFrom = (*TunnelConn)(nil)
)

package masque

import (
	"errors"
	"io"
	"net"
	"time"

	C "github.com/sagernet/sing-box/constant"
)

// connectStreamTunnelConn maps tunnel errors to ErrTCPConnectStreamFailed for template TCP dials.
type connectStreamTunnelConn struct {
	inner net.Conn
}

func (c *connectStreamTunnelConn) Read(p []byte) (int, error) {
	n, err := c.inner.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, errors.Join(ErrTCPConnectStreamFailed, err)
	}
	return n, err
}

func (c *connectStreamTunnelConn) Write(p []byte) (int, error) {
	n, err := c.inner.Write(p)
	if err != nil {
		return n, errors.Join(ErrTCPConnectStreamFailed, err)
	}
	return n, err
}

func (c *connectStreamTunnelConn) Close() error                       { return c.inner.Close() }
func (c *connectStreamTunnelConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *connectStreamTunnelConn) RemoteAddr() net.Addr               { return c.inner.RemoteAddr() }
func (c *connectStreamTunnelConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *connectStreamTunnelConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *connectStreamTunnelConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

func (c *connectStreamTunnelConn) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := c.inner.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(r)
		if err != nil {
			return n, errors.Join(ErrTCPConnectStreamFailed, err)
		}
		return n, nil
	}
	return io.Copy(c, r)
}

func (c *connectStreamTunnelConn) WriteTo(w io.Writer) (int64, error) {
	if wt, ok := c.inner.(io.WriterTo); ok {
		n, err := wt.WriteTo(w)
		if err != nil {
			return n, errors.Join(ErrTCPConnectStreamFailed, err)
		}
		return n, nil
	}
	return io.Copy(w, c.inner)
}

// RouteConnectionCopyWriterTo opts into route io.WriterTo bulk download when the inner conn supports it.
func (c *connectStreamTunnelConn) RouteConnectionCopyWriterTo() {}

var _ C.RouteConnectionCopyWriterTo = (*connectStreamTunnelConn)(nil)

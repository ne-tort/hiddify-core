package connectauthority

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	C "github.com/sagernet/sing-box/constant"
)

// ErrConnectAuthorityFailed is returned for CONNECT-by-authority dial/relay failures.
var ErrConnectAuthorityFailed = errors.New("masque tcp connect_authority failed")

// ErrDeadlineUnsupported is returned when the underlying stream does not support deadlines.
var ErrDeadlineUnsupported = errors.New("deadline not supported")

// Conn is a full-duplex TCP shim over one HTTP/3 CONNECT stream (RFC 9114 tunneled TCP).
// Default: Read/Write on *http3.Stream. Optional pipe upload when MASQUE_*_PIPE_UPLOAD=1.
type Conn struct {
	h3     *http3.Stream
	reader io.ReadCloser
	writer io.WriteCloser
	ctx    context.Context
	cancel context.CancelFunc
	local  net.Addr
	remote net.Addr

	readMu  sync.Mutex
	writeMu sync.Mutex
	readDL  time.Time
	writeDL time.Time
}

type ConnParams struct {
	H3Stream *http3.Stream
	Reader   io.ReadCloser
	Writer   io.WriteCloser
	Ctx      context.Context
	Local    net.Addr
	Remote   net.Addr
}

func NewConn(p ConnParams) *Conn {
	ctx := p.Ctx
	var cancel context.CancelFunc
	if ctx == nil {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	return &Conn{
		h3:     p.H3Stream,
		reader: p.Reader,
		writer: p.Writer,
		ctx:    ctx,
		cancel: cancel,
		local:  p.Local,
		remote: p.Remote,
	}
}

func (c *Conn) usesH3Stream() bool {
	return c != nil && c.h3 != nil
}

func (c *Conn) Read(p []byte) (int, error) {
	if c == nil {
		return 0, io.EOF
	}
	if c.h3 != nil {
		c.readMu.Lock()
		dl := c.readDL
		c.readMu.Unlock()
		if !dl.IsZero() {
			_ = c.h3.SetReadDeadline(dl)
		}
		if err := c.ctx.Err(); err != nil {
			return 0, err
		}
		n, err := c.h3.Read(p)
		if err != nil {
			err = errors.Join(ErrConnectAuthorityFailed, err)
		}
		return n, err
	}
	if c.reader == nil {
		return 0, io.EOF
	}
	c.readMu.Lock()
	dl := c.readDL
	c.readMu.Unlock()
	if !dl.IsZero() {
		if d, ok := c.reader.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = d.SetReadDeadline(dl)
		} else if time.Now().After(dl) {
			return 0, ErrDeadlineUnsupported
		}
	}
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.reader.Read(p)
	if err != nil {
		err = errors.Join(ErrConnectAuthorityFailed, err)
	}
	return n, err
}

func (c *Conn) Write(p []byte) (int, error) {
	if c == nil {
		return 0, io.ErrClosedPipe
	}
	if c.h3 != nil {
		c.writeMu.Lock()
		dl := c.writeDL
		c.writeMu.Unlock()
		if !dl.IsZero() {
			_ = c.h3.SetWriteDeadline(dl)
		}
		if err := c.ctx.Err(); err != nil {
			return 0, err
		}
		n, err := c.h3.Write(p)
		if err != nil {
			err = errors.Join(ErrConnectAuthorityFailed, err)
		}
		return n, err
	}
	if c.writer == nil {
		return 0, io.ErrClosedPipe
	}
	c.writeMu.Lock()
	dl := c.writeDL
	c.writeMu.Unlock()
	if !dl.IsZero() {
		if d, ok := c.writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = d.SetWriteDeadline(dl)
		} else if time.Now().After(dl) {
			return 0, ErrDeadlineUnsupported
		}
	}
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.writer.Write(p)
	if err != nil {
		err = errors.Join(ErrConnectAuthorityFailed, err)
	}
	return n, err
}

func (c *Conn) ReadFrom(r io.Reader) (int64, error) {
	if c.h3 != nil {
		return io.Copy(c.h3, r)
	}
	if c.writer == nil {
		return 0, io.ErrClosedPipe
	}
	return io.Copy(c.writer, r)
}

func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	if c.h3 != nil {
		return io.Copy(w, c.h3)
	}
	if c.reader == nil {
		return 0, io.EOF
	}
	return io.Copy(w, c.reader)
}

func (c *Conn) Close() error {
	c.cancel()
	var err error
	if c.h3 != nil {
		c.h3.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		if closeErr := c.h3.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}
	if c.reader != nil {
		err = errors.Join(err, c.reader.Close())
	}
	if c.writer != nil {
		err = errors.Join(err, c.writer.Close())
	}
	return err
}

func (c *Conn) LocalAddr() net.Addr {
	if c != nil && c.local != nil {
		return c.local
	}
	return &net.TCPAddr{}
}

func (c *Conn) RemoteAddr() net.Addr {
	if c != nil && c.remote != nil {
		return c.remote
	}
	return &net.TCPAddr{}
}

func (c *Conn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readMu.Lock()
	c.readDL = t
	c.readMu.Unlock()
	if c.h3 != nil {
		return c.h3.SetReadDeadline(t)
	}
	if d, ok := c.reader.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return ErrDeadlineUnsupported
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeMu.Lock()
	c.writeDL = t
	c.writeMu.Unlock()
	if c.h3 != nil {
		return c.h3.SetWriteDeadline(t)
	}
	if d, ok := c.writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(t)
	}
	return ErrDeadlineUnsupported
}

// RouteConnectionCopyWriterTo opts into route bulk download via io.WriterTo (sing-box).
func (*Conn) RouteConnectionCopyWriterTo() {}

var (
	_ io.WriterTo                   = (*Conn)(nil)
	_ io.ReaderFrom                 = (*Conn)(nil)
	_ C.RouteConnectionCopyWriterTo = (*Conn)(nil)
)

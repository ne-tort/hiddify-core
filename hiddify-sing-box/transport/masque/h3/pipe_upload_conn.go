package h3

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// PipeUploadTunnelConnParams configures legacy pipe_upload reader/writer split (tests only).
type PipeUploadTunnelConnParams struct {
	Reader io.ReadCloser
	Writer io.WriteCloser
	Ctx    context.Context
	Local  net.Addr
	Remote net.Addr
}

// PipeUploadTunnelConn is the legacy pipe_upload shim (separate download Reader + upload Writer).
// Prod CONNECT-stream dial uses TunnelConn over one *http3.Stream only.
type PipeUploadTunnelConn struct {
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

// NewPipeUploadTunnelConn builds a test-only pipe_upload tunnel (not prod dial).
func NewPipeUploadTunnelConn(p PipeUploadTunnelConnParams) *PipeUploadTunnelConn {
	ctx := p.Ctx
	var cancel context.CancelFunc
	if ctx == nil {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	return &PipeUploadTunnelConn{
		reader: p.Reader,
		writer: p.Writer,
		ctx:    ctx,
		cancel: cancel,
		local:  p.Local,
		remote: p.Remote,
	}
}

func (c *PipeUploadTunnelConn) Read(p []byte) (int, error) {
	if c == nil {
		return 0, io.EOF
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
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	return n, err
}

func (c *PipeUploadTunnelConn) Write(p []byte) (int, error) {
	if c == nil {
		return 0, io.ErrClosedPipe
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
	n, err := writeChunked(c.writer, p, H3UploadFlushChunkBytes)
	if err != nil {
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	return n, err
}

func (c *PipeUploadTunnelConn) ReadFrom(r io.Reader) (int64, error) {
	if c == nil || c.writer == nil {
		return 0, io.ErrClosedPipe
	}
	n, err := copyChunked(c.writer, r, H3UploadFlushChunkBytes)
	if err != nil {
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	return n, err
}

func (c *PipeUploadTunnelConn) WriteTo(w io.Writer) (int64, error) {
	if c == nil || c.reader == nil {
		return 0, io.EOF
	}
	return io.Copy(w, c.reader)
}

func (c *PipeUploadTunnelConn) Close() error {
	if c == nil {
		return nil
	}
	c.cancel()
	var err error
	if c.reader != nil {
		err = errors.Join(err, c.reader.Close())
	}
	if c.writer != nil {
		err = errors.Join(err, c.writer.Close())
	}
	return err
}

func (c *PipeUploadTunnelConn) LocalAddr() net.Addr {
	if c != nil && c.local != nil {
		return c.local
	}
	return &net.TCPAddr{}
}

func (c *PipeUploadTunnelConn) RemoteAddr() net.Addr {
	if c != nil && c.remote != nil {
		return c.remote
	}
	return &net.TCPAddr{}
}

func (c *PipeUploadTunnelConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}

func (c *PipeUploadTunnelConn) SetReadDeadline(t time.Time) error {
	if c == nil {
		return nil
	}
	c.readMu.Lock()
	c.readDL = t
	c.readMu.Unlock()
	if d, ok := c.reader.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return ErrDeadlineUnsupported
}

func (c *PipeUploadTunnelConn) SetWriteDeadline(t time.Time) error {
	if c == nil {
		return nil
	}
	c.writeMu.Lock()
	c.writeDL = t
	c.writeMu.Unlock()
	if d, ok := c.writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(t)
	}
	return ErrDeadlineUnsupported
}

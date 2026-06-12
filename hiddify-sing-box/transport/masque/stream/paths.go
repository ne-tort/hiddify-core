package stream

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	C "github.com/sagernet/sing-box/constant"
)

// DownloadPath is the CONNECT-stream download half (response body / stream read).
type DownloadPath interface {
	io.Reader
	io.Closer
}

// UploadPath is the CONNECT-stream upload half (request body / stream write).
type UploadPath interface {
	io.Writer
	io.Closer
}

// TunnelPaths pairs explicit upload/download halves of an RFC 8441 / 9114 bidi tunnel.
type TunnelPaths struct {
	Download DownloadPath
	Upload   UploadPath
}

type downloadPathAdapter struct {
	inner io.ReadCloser
}

func (a *downloadPathAdapter) Read(p []byte) (int, error) { return a.inner.Read(p) }

func (a *downloadPathAdapter) Close() error {
	if a.inner == nil {
		return nil
	}
	return a.inner.Close()
}

type uploadPathAdapter struct {
	inner io.WriteCloser
}

func (a *uploadPathAdapter) Write(p []byte) (int, error) { return a.inner.Write(p) }

func (a *uploadPathAdapter) Close() error {
	if a.inner == nil {
		return nil
	}
	return a.inner.Close()
}

// NewH2DownloadPath wraps the H2 CONNECT response body for deadline-aware download I/O.
func NewH2DownloadPath(body io.ReadCloser) DownloadPath {
	if body == nil {
		return nil
	}
	return &downloadPathAdapter{inner: NewH2ConnectStreamResponseBody(body)}
}

// NewUploadPath wraps a request-body writer as an explicit upload half.
func NewUploadPath(w io.WriteCloser) UploadPath {
	if w == nil {
		return nil
	}
	return &uploadPathAdapter{inner: w}
}

// NewTunnelPaths pairs explicit upload/download halves without H2-specific upload policy.
// Production H2 CONNECT-stream uses h2.NewTunnelPaths for chunked upload.
func NewTunnelPaths(body io.ReadCloser, upload io.WriteCloser) TunnelPaths {
	return TunnelPaths{
		Download: NewH2DownloadPath(body),
		Upload:   NewUploadPath(upload),
	}
}

// ConnFromTunnelPaths assembles net.Conn from explicit upload/download halves.
func ConnFromTunnelPaths(ctx context.Context, paths TunnelPaths, local, remote net.Addr) net.Conn {
	return &bidiTunnelConn{
		ctx:    ctx,
		paths:  paths,
		local:  local,
		remote: remote,
	}
}

// bidiTunnelConn implements net.Conn over explicit TunnelPaths (H2 thin tunnel today).
type bidiTunnelConn struct {
	ctx      context.Context
	paths    TunnelPaths
	local    net.Addr
	remote   net.Addr
	uploadDL connDeadlines
	uploadMu sync.Mutex
}

func (c *bidiTunnelConn) Read(p []byte) (int, error) {
	if c.ctx != nil {
		if err := context.Cause(c.ctx); err != nil {
			return 0, err
		}
	}
	if c.paths.Download == nil {
		return 0, io.EOF
	}
	n, err := c.paths.Download.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, errors.Join(Errs.TCPConnectStreamFailed, err)
	}
	return n, err
}

func (c *bidiTunnelConn) Write(p []byte) (int, error) {
	c.uploadMu.Lock()
	defer c.uploadMu.Unlock()
	if c.uploadDL.writeTimeoutExceeded() {
		return 0, errors.Join(Errs.TCPConnectStreamFailed, os.ErrDeadlineExceeded)
	}
	if wNanos := c.uploadDL.write.Load(); wNanos != 0 && time.Now().UnixNano() > wNanos {
		return 0, errors.Join(Errs.TCPConnectStreamFailed, os.ErrDeadlineExceeded)
	}
	if c.paths.Upload == nil {
		return 0, io.ErrClosedPipe
	}
	n, err := c.paths.Upload.Write(p)
	if err != nil {
		return n, errors.Join(Errs.TCPConnectStreamFailed, err)
	}
	return n, nil
}

func (c *bidiTunnelConn) ReadFrom(r io.Reader) (int64, error) {
	c.uploadMu.Lock()
	defer c.uploadMu.Unlock()
	if c.paths.Upload == nil {
		return 0, io.ErrClosedPipe
	}
	n, err := io.Copy(c.paths.Upload, r)
	if err != nil {
		return n, errors.Join(Errs.TCPConnectStreamFailed, err)
	}
	return n, nil
}

func (c *bidiTunnelConn) WriteTo(w io.Writer) (int64, error) {
	if c.paths.Download == nil {
		return 0, io.EOF
	}
	n, err := io.Copy(w, c.paths.Download)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, errors.Join(Errs.TCPConnectStreamFailed, err)
	}
	return n, err
}

func (c *bidiTunnelConn) Close() error {
	var err error
	if c.paths.Upload != nil {
		err = errors.Join(err, c.paths.Upload.Close())
	}
	if c.paths.Download != nil {
		err = errors.Join(err, c.paths.Download.Close())
	}
	return err
}

func (c *bidiTunnelConn) CloseWrite() error {
	if c.paths.Upload == nil {
		return nil
	}
	return c.paths.Upload.Close()
}

func (c *bidiTunnelConn) LocalAddr() net.Addr  { return c.local }
func (c *bidiTunnelConn) RemoteAddr() net.Addr { return c.remote }

func (c *bidiTunnelConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}

func (c *bidiTunnelConn) SetReadDeadline(t time.Time) error {
	if c.paths.Download == nil {
		return ErrDeadlineUnsupported
	}
	if d, ok := c.paths.Download.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return ErrDeadlineUnsupported
}

func (c *bidiTunnelConn) SetWriteDeadline(t time.Time) error {
	c.uploadDL.setWriteDeadline(t)
	return nil
}

func (*bidiTunnelConn) RouteConnectionCopyWriterTo() {}

var (
	_ io.ReaderFrom                 = (*bidiTunnelConn)(nil)
	_ io.WriterTo                   = (*bidiTunnelConn)(nil)
	_ C.RouteConnectionCopyWriterTo = (*bidiTunnelConn)(nil)
)

package stream

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/sagernet/sing-box/constant"
)

const bidiTunnelWriteToBufLen = 64 * 1024

var bidiTunnelWriteToBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, bidiTunnelWriteToBufLen)
		return &b
	},
}

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
	inner  io.ReadCloser
	readMu sync.Mutex // serialize drain vs Read vs WriteTo on one H2 response body
}

func (a *downloadPathAdapter) Read(p []byte) (int, error) {
	if a == nil || a.inner == nil {
		return 0, io.EOF
	}
	a.readMu.Lock()
	defer a.readMu.Unlock()
	return a.inner.Read(p)
}

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
	c := &bidiTunnelConn{
		ctx:    ctx,
		paths:  paths,
		local:  local,
		remote: remote,
	}
	c.maybeStartDownloadDrain()
	return c
}

// bidiTunnelConn implements net.Conn over explicit TunnelPaths (H2 thin tunnel today).
type bidiTunnelConn struct {
	ctx      context.Context
	paths    TunnelPaths
	local    net.Addr
	remote   net.Addr
	uploadDL connDeadlines
	uploadMu sync.Mutex

	downloadMu     sync.Mutex
	drainOnce      sync.Once
	drainStopped   int32
	downloadActive int32 // WriteTo in progress — H2 bidi upload scheduling (parity h3.TunnelConn)
}

func readDownloadPath(dl DownloadPath, p []byte) (int, error) {
	if dl == nil {
		return 0, io.EOF
	}
	n, err := dl.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, errors.Join(Errs.TCPConnectStreamFailed, err)
	}
	return n, err
}

func (c *bidiTunnelConn) readDownloadLocked(p []byte) (int, error) {
	return readDownloadPath(c.paths.Download, p)
}

func (c *bidiTunnelConn) stopDownloadDrain() {
	atomic.StoreInt32(&c.drainStopped, 1)
}

func (c *bidiTunnelConn) maybeStartDownloadDrain() {
	if !H2BidiDownloadDrainEnabled() || c.paths.Download == nil {
		return
	}
	c.drainOnce.Do(func() {
		go c.runDownloadDrain()
	})
}

func (c *bidiTunnelConn) runDownloadDrain() {
	buf := make([]byte, 32*1024)
	for {
		if c.ctx != nil {
			if err := context.Cause(c.ctx); err != nil {
				return
			}
		}
		if atomic.LoadInt32(&c.drainStopped) > 0 || atomic.LoadInt32(&c.downloadActive) > 0 {
			return
		}
		if c.paths.Download == nil {
			return
		}
		n, err := readDownloadPath(c.paths.Download, buf)
		if n > 0 {
			continue
		}
		if err != nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func (c *bidiTunnelConn) Read(p []byte) (int, error) {
	if c.ctx != nil {
		if err := context.Cause(c.ctx); err != nil {
			return 0, err
		}
	}
	c.stopDownloadDrain()
	c.downloadMu.Lock()
	defer c.downloadMu.Unlock()
	return c.readDownloadLocked(p)
}

func (c *bidiTunnelConn) Write(p []byte) (int, error) {
	c.maybeStartDownloadDrain()
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
	c.maybeStartDownloadDrain()
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
	c.stopDownloadDrain()
	atomic.AddInt32(&c.downloadActive, 1)
	defer atomic.AddInt32(&c.downloadActive, -1)
	bp := bidiTunnelWriteToBufPool.Get().(*[]byte)
	defer bidiTunnelWriteToBufPool.Put(bp)
	reader := &bidiTunnelDownloadReader{c: c}
	n, err := io.CopyBuffer(w, reader, *bp)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, errors.Join(Errs.TCPConnectStreamFailed, err)
	}
	return n, err
}

// DownloadActive reports whether WriteTo is draining the response half (iperf -R duplex).
func (c *bidiTunnelConn) DownloadActive() bool {
	return c != nil && atomic.LoadInt32(&c.downloadActive) > 0
}

type bidiTunnelDownloadReader struct {
	c *bidiTunnelConn
}

func (r *bidiTunnelDownloadReader) Read(p []byte) (int, error) {
	if r == nil || r.c == nil {
		return 0, io.EOF
	}
	r.c.downloadMu.Lock()
	defer r.c.downloadMu.Unlock()
	return r.c.readDownloadLocked(p)
}

func (c *bidiTunnelConn) Close() error {
	c.stopDownloadDrain()
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

func (*bidiTunnelConn) RouteConnectionCopyReaderFrom() {}

var (
	_ io.ReaderFrom                   = (*bidiTunnelConn)(nil)
	_ io.WriterTo                     = (*bidiTunnelConn)(nil)
	_ C.RouteConnectionCopyWriterTo   = (*bidiTunnelConn)(nil)
	_ C.RouteConnectionCopyReaderFrom = (*bidiTunnelConn)(nil)
)

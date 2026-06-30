package conn

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

func (a *downloadPathAdapter) SetReadDeadline(t time.Time) error {
	if a == nil || a.inner == nil {
		return ErrDeadlineUnsupported
	}
	if d, ok := a.inner.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return ErrDeadlineUnsupported
}

type uploadPathAdapter struct {
	inner io.WriteCloser
}

func (a *uploadPathAdapter) Write(p []byte) (int, error) { return a.inner.Write(p) }

func (a *uploadPathAdapter) Flush() error {
	if a == nil || a.inner == nil {
		return nil
	}
	if f, ok := a.inner.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	if fl, ok := a.inner.(interface{ Flush() }); ok {
		fl.Flush()
	}
	return nil
}

func (a *uploadPathAdapter) Close() error {
	if a.inner == nil {
		return nil
	}
	return a.inner.Close()
}

func (a *uploadPathAdapter) PokeH2BidiDownload() {
	if a == nil || a.inner == nil {
		return
	}
	if p, ok := a.inner.(interface{ PokeH2BidiDownload() }); ok {
		p.PokeH2BidiDownload()
	}
}

// NewDownloadPathAdapter wraps a read-closer with production download-path mutex serialization.
func NewDownloadPathAdapter(inner io.ReadCloser) DownloadPath {
	if inner == nil {
		return nil
	}
	return &downloadPathAdapter{inner: inner}
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
// Production H2 CONNECT-stream uses h2.NewTunnelPaths (bulk upload passthrough).
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

	downloadMu     sync.Mutex
	drainOnce      sync.Once
	drainStopped   int32
	duplexCopy     int32 // ConnectionManager runs ReadFrom+WriteTo concurrently
	downloadActive int32 // WriteTo in progress вЂ” H2 bidi upload scheduling (parity h3.TunnelConn)
	bootstrapUploadDone int32 // one-shot upload DATA before first download read (iperf -R)
}

// MarkConnectionCopyDuplex opts out of upload-only download drain; prod SOCKS/TUN relay uses WriteTo.
func (c *bidiTunnelConn) MarkConnectionCopyDuplex() {
	if c == nil {
		return
	}
	atomic.StoreInt32(&c.duplexCopy, 1)
}

func readDownloadPath(dl DownloadPath, p []byte) (int, error) {
	if dl == nil {
		return 0, io.EOF
	}
	n, err := dl.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, errors.Join(tcpConnectStreamFailed, err)
	}
	return n, err
}

func (c *bidiTunnelConn) setDownloadReadDeadline(t time.Time) error {
	if c == nil || c.paths.Download == nil {
		return ErrDeadlineUnsupported
	}
	if d, ok := c.paths.Download.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return ErrDeadlineUnsupported
}

func (c *bidiTunnelConn) stopDownloadDrain() {
	if atomic.SwapInt32(&c.drainStopped, 1) == 1 {
		return
	}
	_ = c.setDownloadReadDeadline(time.Now())
}

func (c *bidiTunnelConn) maybeStartDownloadDrainOnUpload() {
	if c == nil || atomic.LoadInt32(&c.duplexCopy) > 0 {
		return
	}
	c.maybeStartDownloadDrain()
}

func (c *bidiTunnelConn) maybeStartDownloadDrain() {
	if c.paths.Download == nil {
		return
	}
	if atomic.LoadInt32(&c.duplexCopy) > 0 ||
		atomic.LoadInt32(&c.downloadActive) > 0 ||
		atomic.LoadInt32(&c.drainStopped) > 0 {
		return
	}
	c.drainOnce.Do(func() {
		go c.runDownloadDrain()
	})
}

func (c *bidiTunnelConn) runDownloadDrain() {
	const drainPollInterval = 50 * time.Millisecond
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
		c.downloadMu.Lock()
		if atomic.LoadInt32(&c.drainStopped) > 0 || atomic.LoadInt32(&c.downloadActive) > 0 {
			c.downloadMu.Unlock()
			return
		}
		_ = c.setDownloadReadDeadline(time.Now().Add(drainPollInterval))
		n, err := readDownloadPath(c.paths.Download, buf)
		_ = c.setDownloadReadDeadline(time.Time{})
		c.downloadMu.Unlock()
		if n > 0 {
			continue
		}
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
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
	_ = c.setDownloadReadDeadline(time.Time{})
	return readDownloadPath(c.paths.Download, p)
}

func (c *bidiTunnelConn) Write(p []byte) (int, error) {
	c.uploadMu.Lock()
	defer c.uploadMu.Unlock()
	if c.uploadDL.writeTimeoutExceeded() {
		return 0, errors.Join(tcpConnectStreamFailed, os.ErrDeadlineExceeded)
	}
	if wNanos := c.uploadDL.write.Load(); wNanos != 0 && time.Now().UnixNano() > wNanos {
		return 0, errors.Join(tcpConnectStreamFailed, os.ErrDeadlineExceeded)
	}
	if c.paths.Upload == nil {
		return 0, io.ErrClosedPipe
	}
	n, err := c.paths.Upload.Write(p)
	if err != nil {
		return n, errors.Join(tcpConnectStreamFailed, err)
	}
	return n, nil
}

func (c *bidiTunnelConn) ReadFrom(r io.Reader) (int64, error) {
	c.maybeStartDownloadDrainOnUpload()
	if c.paths.Upload == nil {
		return 0, io.ErrClosedPipe
	}
	chunk := H2ConnectUploadChunkBytes()
	if chunk <= 0 {
		c.uploadMu.Lock()
		defer c.uploadMu.Unlock()
		n, err := io.Copy(c.paths.Upload, r)
		if err != nil {
			return n, errors.Join(tcpConnectStreamFailed, err)
		}
		return n, nil
	}
	buf := make([]byte, chunk)
	var total int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			c.uploadMu.Lock()
			wrote, werr := c.paths.Upload.Write(buf[:n])
			c.uploadMu.Unlock()
			if werr != nil {
				return total, errors.Join(tcpConnectStreamFailed, werr)
			}
			total += int64(wrote)
			if wrote < n {
				return total, errors.Join(tcpConnectStreamFailed, io.ErrShortWrite)
			}
			pokeUploadPathForH2BidiDownload(c.paths.Upload)
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, errors.Join(tcpConnectStreamFailed, err)
		}
	}
}

func (c *bidiTunnelConn) WriteTo(w io.Writer) (int64, error) {
	if c.paths.Download == nil {
		return 0, io.EOF
	}
	atomic.AddInt32(&c.downloadActive, 1)
	defer atomic.AddInt32(&c.downloadActive, -1)
	c.stopDownloadDrain()
	// H2 bidi FC: poke upload before first response read (iperf -R banner / docker download leg).
	c.wakeH2BidiUploadDuringDownload()
	bp := bidiTunnelWriteToBufPool.Get().(*[]byte)
	defer bidiTunnelWriteToBufPool.Put(bp)
	reader := &bidiTunnelDownloadReader{c: c}
	n, err := io.CopyBuffer(w, reader, *bp)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, errors.Join(tcpConnectStreamFailed, err)
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
	r.c.wakeH2BidiUploadDuringDownload()
	r.c.downloadMu.Lock()
	defer r.c.downloadMu.Unlock()
	_ = r.c.setDownloadReadDeadline(time.Time{})
	n, err := readDownloadPath(r.c.paths.Download, p)
	if n > 0 {
		r.c.wakeH2BidiUploadDuringDownload()
	}
	return n, err
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
	_ C.RouteConnectionCopyDuplex     = (*bidiTunnelConn)(nil)
)

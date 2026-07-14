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

// ErrTunnelConnFailed is returned for H3 CONNECT tunnel dial/relay failures.
var ErrTunnelConnFailed = errors.New("masque h3 connect tunnel failed")

// ErrDeadlineUnsupported is returned when the underlying stream does not support deadlines.
var ErrDeadlineUnsupported = errors.New("deadline not supported")

// connectStreamBufLen matches h2o proxy.max-buffer-size (64 KiB).
const connectStreamBufLen = 64 * 1024

// H3UploadFlushChunkBytes is the route ReadFrom / bulk upload buffer (h2o parity).
const H3UploadFlushChunkBytes = connectStreamBufLen

// TunnelWriteToBufLen is the route WriteTo / ReadFrom buffer (h2o parity).
const TunnelWriteToBufLen = connectStreamBufLen

// connectStreamDownloadCloseTimeout bounds H3 stream Close during tunnel teardown.
const connectStreamDownloadCloseTimeout = 2 * time.Second

// TunnelConn is a thin net.Conn over one HTTP/3 CONNECT bidi stream (Invisv parity).
type TunnelConn struct {
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
	uploadEOFClosed      int32
	downloadActive       int32
	requestCancel        context.CancelCauseFunc
	requestCancelOnce    sync.Once
	closeFullOnce        sync.Once
	closeDoneOnce        sync.Once
	closeDone            chan struct{}
}

// TunnelConnParams configures a TunnelConn over HTTP/3 CONNECT.
type TunnelConnParams struct {
	H3Stream h3ConnectStream
	Ctx      context.Context
	Local    net.Addr
	Remote   net.Addr
}

// NewTunnelConn builds a tunneled net.Conn over one HTTP/3 CONNECT stream.
func NewTunnelConn(p TunnelConnParams) *TunnelConn {
	applyTunnelConnParamsHook(&p)
	ctx := p.Ctx
	var cancel context.CancelFunc
	if ctx == nil {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	return &TunnelConn{
		h3:        p.H3Stream,
		ctx:       ctx,
		cancel:    cancel,
		local:     p.Local,
		remote:    p.Remote,
		closeDone: make(chan struct{}),
	}
}

// UsesH3Stream reports whether upload/download share one *http3.Stream.
func (c *TunnelConn) UsesH3Stream() bool {
	return c != nil && c.h3 != nil
}

// DownloadActive reports whether WriteTo is draining the response half.
func (c *TunnelConn) DownloadActive() bool {
	return c != nil && atomic.LoadInt32(&c.downloadActive) > 0
}

func (c *TunnelConn) ConnectStreamCloseDone() <-chan struct{} {
	if c == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	return c.closeDone
}

func (c *TunnelConn) SetConnectStreamRequestCancel(cancel context.CancelCauseFunc) {
	if c != nil {
		c.requestCancel = cancel
	}
}

func (c *TunnelConn) LocalAddr() net.Addr  { return c.local }
func (c *TunnelConn) RemoteAddr() net.Addr { return c.remote }

func (c *TunnelConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *TunnelConn) SetReadDeadline(t time.Time) error {
	if c == nil {
		return ErrDeadlineUnsupported
	}
	c.readMu.Lock()
	c.readDL = t
	c.readMu.Unlock()
	if c.h3 != nil {
		return c.h3.SetReadDeadline(t)
	}
	return ErrDeadlineUnsupported
}

func (c *TunnelConn) SetWriteDeadline(t time.Time) error {
	if c == nil {
		return ErrDeadlineUnsupported
	}
	c.writeMu.Lock()
	c.writeDL = t
	c.writeMu.Unlock()
	if c.h3 != nil {
		return c.h3.SetWriteDeadline(t)
	}
	return ErrDeadlineUnsupported
}

func (c *TunnelConn) Read(p []byte) (int, error) {
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

func (c *TunnelConn) Write(p []byte) (int, error) {
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

type tunnelUploadWriter struct{ c *TunnelConn }

func (w tunnelUploadWriter) Write(p []byte) (int, error) { return w.c.Write(p) }

func (c *TunnelConn) ReadFrom(r io.Reader) (int64, error) {
	if c == nil || c.h3 == nil {
		return 0, io.ErrClosedPipe
	}
	buf := make([]byte, connectStreamBufLen)
	n, err := io.CopyBuffer(tunnelUploadWriter{c}, r, buf)
	if err != nil && !errors.Is(err, io.EOF) {
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	return n, err
}

type tunnelDownloadReader struct{ c *TunnelConn }

func (r tunnelDownloadReader) Read(p []byte) (int, error) { return r.c.Read(p) }

func (c *TunnelConn) WriteTo(w io.Writer) (int64, error) {
	if c == nil || c.h3 == nil {
		return 0, io.EOF
	}
	c.beginDownload()
	defer c.endDownload()
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	buf := make([]byte, connectStreamBufLen)
	n, err := io.CopyBuffer(w, tunnelDownloadReader{c}, buf)
	if err != nil && !errors.Is(err, io.EOF) {
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	return n, err
}

func (c *TunnelConn) MarkConnectionCopyDuplex() {}

func (c *TunnelConn) beginDownload() {
	if c == nil {
		return
	}
	atomic.AddInt32(&c.downloadActive, 1)
	if testBidiDownloadActiveHook != nil {
		testBidiDownloadActiveHook(true)
	}
	if TestDuplexDownloadArmedHook != nil {
		select {
		case TestDuplexDownloadArmedHook <- struct{}{}:
		default:
		}
	}
}

func (c *TunnelConn) endDownload() {
	if c == nil {
		return
	}
	atomic.AddInt32(&c.downloadActive, -1)
	if testBidiDownloadActiveHook != nil {
		testBidiDownloadActiveHook(false)
	}
	if atomic.LoadInt32(&c.uploadEOFClosed) != 0 {
		var err error
		c.closeFullOnce.Do(func() { err = c.closeFull() })
		_ = err
	}
}

func (c *TunnelConn) CloseWrite() error {
	if c == nil || c.h3 == nil {
		return nil
	}
	atomic.StoreInt32(&c.uploadEOFClosed, 1)
	return c.h3.Close()
}

func (c *TunnelConn) Close() error {
	if c == nil {
		return nil
	}
	if atomic.LoadInt32(&c.downloadActive) > 0 {
		if atomic.LoadInt32(&c.uploadEOFClosed) != 0 {
			return c.CloseWrite()
		}
		var err error
		c.closeFullOnce.Do(func() { err = c.closeFull() })
		return err
	}
	var err error
	c.closeFullOnce.Do(func() { err = c.closeFull() })
	return err
}

func (c *TunnelConn) closeFull() error {
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
		// Always finish both halves: Close() = send FIN; CancelRead completes receive
		// locally and STOP_SENDING so the peer (server) can free MaxIncomingStreams.
		// Idle-only Close() left ghost streams after abrupt browser/speedtest reloads.
		closeDone := make(chan error, 1)
		go func() {
			closeDone <- h3.Close()
		}()
		select {
		case closeErr := <-closeDone:
			if closeErr != nil {
				err = errors.Join(err, closeErr)
			}
		case <-time.After(connectStreamDownloadCloseTimeout):
			h3.CancelWrite(cancelCode)
		}
		h3.CancelRead(cancelCode)
		c.markCloseDone()
	} else {
		c.markCloseDone()
	}
	return err
}

func (c *TunnelConn) markCloseDone() {
	if c == nil {
		return
	}
	c.closeDoneOnce.Do(func() {
		if c.closeDone != nil {
			close(c.closeDone)
		}
	})
}

func (*TunnelConn) RouteConnectionCopyWriterTo()   {}
func (*TunnelConn) RouteConnectionCopyReaderFrom() {}

var (
	_ TunnelFacade                    = (*TunnelConn)(nil)
	_ C.RouteConnectionCopyWriterTo   = (*TunnelConn)(nil)
	_ C.RouteConnectionCopyReaderFrom = (*TunnelConn)(nil)
	_ C.RouteConnectionCopyDuplex     = (*TunnelConn)(nil)
)

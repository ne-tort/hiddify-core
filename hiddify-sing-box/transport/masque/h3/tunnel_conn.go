package h3

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	C "github.com/sagernet/sing-box/constant"
	strmconn "github.com/sagernet/sing-box/transport/masque/stream/conn"
)

// ErrTunnelConnFailed is returned for H3 CONNECT tunnel dial/relay failures.
var ErrTunnelConnFailed = errors.New("masque h3 connect tunnel failed")

// ErrDeadlineUnsupported is returned when the underlying stream does not support deadlines.
var ErrDeadlineUnsupported = errors.New("deadline not supported")

// TunnelWriteToBufLen is the prod route WriteTo drain buffer (256 KiB anchor).
const TunnelWriteToBufLen = 256 * 1024

var tunnelWriteToBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, TunnelWriteToBufLen)
		return &b
	},
}

// TunnelConn is a full-duplex TCP shim over one HTTP/3 CONNECT stream (RFC 9114 tunneled TCP).
type TunnelConn struct {
	h3     h3ConnectStream
	ctx    context.Context
	cancel context.CancelFunc
	requestCancel context.CancelCauseFunc
	local  net.Addr
	remote net.Addr

	readMu  sync.Mutex
	writeMu sync.Mutex
	readDL  time.Time
	writeDL time.Time

	downloadActive      int32 // WriteTo in progress — upload wake for iperf -R duplex
	uploadEOFClosed     int32 // route upload leg called CloseWrite before Close
	downloadDelivered   int32 // WriteTo delivered ≥1 response byte — true duplex interleave
	duplexUploadStarted int32 // concurrent upload Write while WriteTo active
	drainOnce           sync.Once
	drainStopped        int32 // background download discard during upload-only (H3 bidi drain)
	downloadReceiveOnce sync.Once
	downloadDeliveryPending int32 // batched WriteTo delivery wake (256 KiB)
	routeBidiDuplex       bool  // route pairs upload Write with concurrent download WriteTo — no auto drain
	bootstrapUploadDone   int32 // one-shot upload DATA before download drain (H2 parity)
	uploadTrafficStarted  int32 // client upload bytes hit the wire before WriteTo bootstrap (real iperf3 cookie)

	requestCancelOnce sync.Once
	closeFullOnce     sync.Once
	closeDoneOnce     sync.Once
	closeDone         chan struct{}

	bidiWakeSink BidiWakeSink

	scheduler *bidiScheduler

	connectStreamRole ConnectStreamRole
}

// TunnelConnParams configures a TunnelConn over HTTP/3 CONNECT.
type TunnelConnParams struct {
	H3Stream     h3ConnectStream
	Ctx          context.Context
	Local        net.Addr
	Remote       net.Addr
	BidiWakeSink BidiWakeSink
	// RouteBidiDuplex: sing-box route runs upload ReadFrom/Write concurrently with download
	// WriteTo on the same CONNECT stream. Auto drain on upload would consume response bytes
	// (e.g. iperf banner) before WriteTo starts — set true for prod CONNECT dial paths.
	RouteBidiDuplex bool
	// ConnectStreamLeg is P2 leg role ("download" / "upload") or "" for single bidi CONNECT.
	ConnectStreamLeg string
}

// NewTunnelConn builds a tunneled net.Conn over one HTTP/3 CONNECT stream.
func NewTunnelConn(p TunnelConnParams) *TunnelConn {
	ctx := p.Ctx
	var cancel context.CancelFunc
	if ctx == nil {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	conn := &TunnelConn{
		h3:                p.H3Stream,
		ctx:               ctx,
		cancel:            cancel,
		local:             p.Local,
		remote:            p.Remote,
		bidiWakeSink:      p.BidiWakeSink,
		routeBidiDuplex:   p.RouteBidiDuplex,
		connectStreamRole: normalizeConnectStreamRole(p.ConnectStreamLeg),
		closeDone:         make(chan struct{}),
	}
	conn.scheduler = newBidiScheduler(conn, ProdConnectStreamSchedPolicy())
	return conn
}

// ConnectStreamCloseDone reports when CONNECT stream close lifecycle is finished.
func (c *TunnelConn) ConnectStreamCloseDone() <-chan struct{} {
	if c == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	return c.closeDone
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

// UsesH3Stream reports whether upload/download share one *http3.Stream (always true for TunnelConn).
func (c *TunnelConn) UsesH3Stream() bool {
	return c != nil && c.h3 != nil
}

func (c *TunnelConn) stopDownloadDrain() {
	atomic.StoreInt32(&c.drainStopped, 1)
	// Always poke: drain may already be stopped but still blocked in h3.Read under readMu.
	if c.h3 != nil {
		_ = c.h3.SetReadDeadline(time.Now())
	}
}

// lockReadMuForWriteTo acquires readMu after background drain releases it (H2 downloadMu parity).
func (c *TunnelConn) lockReadMuForWriteTo() {
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		c.stopDownloadDrain()
		if c.readMu.TryLock() {
			return
		}
		runtime.Gosched()
	}
	c.readMu.Lock()
}

// applyH3ReadDeadlineLocked sets or clears the h3 read deadline under readMu.
// stopDownloadDrain pokes time.Now(); route WriteTo must clear it when readDL is open-ended.
func (c *TunnelConn) applyH3ReadDeadlineLocked() {
	if c == nil {
		return
	}
	if !c.readDL.IsZero() {
		_ = c.h3.SetReadDeadline(c.readDL)
	} else {
		_ = c.h3.SetReadDeadline(time.Time{})
	}
}

func (c *TunnelConn) maybeStartDownloadDrain() {
	if c == nil {
		return
	}
	c.drainOnce.Do(func() {
		go c.runDownloadDrain()
	})
}

// maybeStartDownloadDrainOnUpload starts background response discard only on upload-only
// legs. Route SOCKS/TUN copy always pairs upload with concurrent download WriteTo; auto
// drain there races and eats protocol bytes before WriteTo (docker iperf banner / connect-stream download gate).
func (c *TunnelConn) maybeStartDownloadDrainOnUpload() {
	if c == nil || c.routeBidiDuplex {
		return
	}
	c.maybeStartDownloadDrain()
}

func (c *TunnelConn) runDownloadDrain() {
	pollDrain := true
	strmconn.RunDownloadDrainLoop(strmconn.DownloadDrainConfig{
		CtxDone: func() error { return c.ctx.Err() },
		ShouldStop: func() bool {
			return atomic.LoadInt32(&c.drainStopped) > 0 || c.DownloadActive()
		},
		Iter: func(buf []byte) (int, error) {
			c.readMu.Lock()
			if atomic.LoadInt32(&c.drainStopped) > 0 || c.DownloadActive() {
				c.readMu.Unlock()
				return 0, strmconn.ErrDownloadDrainStop()
			}
			dl := c.readDL
			pollDrain = dl.IsZero()
			if !dl.IsZero() {
				_ = c.h3.SetReadDeadline(dl)
			} else {
				_ = c.h3.SetReadDeadline(time.Now().Add(strmconn.DownloadDrainPollInterval))
			}
			n, err := c.h3.Read(buf)
			if dl.IsZero() {
				_ = c.h3.SetReadDeadline(time.Time{})
			}
			c.readMu.Unlock()
			return n, err
		},
		RetryReadErr: func(err error) bool {
			if !pollDrain {
				return false
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return true
			}
			return false
		},
	})
}

func (c *TunnelConn) Read(p []byte) (int, error) {
	if c == nil || c.h3 == nil {
		return 0, io.EOF
	}
	c.stopDownloadDrain()
	c.activateDownloadReceiveOnRead()
	c.readMu.Lock()
	defer c.readMu.Unlock()
	c.applyH3ReadDeadlineLocked()
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.h3.Read(p)
	if err != nil {
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	if n > 0 {
		c.scheduler.noteDownloadDelivery(n)
	}
	return n, err
}

func (c *TunnelConn) Write(p []byte) (int, error) {
	if c == nil || c.h3 == nil {
		return 0, io.ErrClosedPipe
	}
	if len(p) > 0 {
		atomic.StoreInt32(&c.uploadTrafficStarted, 1)
		if qs := c.h3.QUICStream(); qs != nil {
			quic.MasqueSetConcurrentUploadPending(qs, true)
		}
	}
	c.maybeStartDownloadDrainOnUpload()
	n, err := c.writeH3Thin(p)
	if err != nil {
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	return n, err
}

func (c *TunnelConn) ReadFrom(r io.Reader) (int64, error) {
	if c == nil || c.h3 == nil {
		return 0, io.ErrClosedPipe
	}
	c.maybeStartDownloadDrainOnUpload()
	n, err := c.readFromH3Thin(r)
	if err != nil {
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	return n, err
}

func (c *TunnelConn) WriteTo(w io.Writer) (int64, error) {
	if c == nil || c.h3 == nil {
		return 0, io.EOF
	}
	n, err := c.writeH3DownloadToThin(w)
	if err != nil {
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	return n, err
}

// writeH3Thin writes upload bytes directly to the CONNECT stream (Invisv parity).
func (c *TunnelConn) writeH3Thin(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeH3UploadLocked(p)
}

func (c *TunnelConn) writeH3UploadLocked(p []byte) (int, error) {
	dl := c.writeDL
	if !dl.IsZero() {
		_ = c.h3.SetWriteDeadline(dl)
	}
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	if !c.routeBidiDuplex && !c.DownloadActive() {
		c.ensureH3BootstrapBeforeUploadLocked()
	}
	if c.DownloadActive() {
		c.noteDuplexUploadTraffic()
	}
	chunkBytes := c.scheduler.uploadChunkBytes()
	var n int
	var err error
	if c.DownloadActive() && len(p) > chunkBytes {
		n, err = writeChunkedWake(c.h3, p, chunkBytes, func(wrote int) {
			if wrote > 0 && c.DownloadActive() {
				if f, ok := c.h3.(interface{ FlushMasqueCoalesce() error }); ok {
					_ = f.FlushMasqueCoalesce()
				}
				c.scheduler.wakeAfterUpload()
			}
		})
	} else {
		n, err = c.h3.Write(p)
		if err == nil && c.DownloadActive() {
			c.scheduler.wakeAfterUpload()
		}
	}
	if n > 0 {
		c.noteUploadTrafficStarted()
		if c.routeBidiDuplex && !c.DownloadActive() && atomic.LoadInt32(&c.duplexUploadStarted) == 0 {
			c.preemptiveArmDuplexQUIC()
		}
	}
	if err == nil {
		if f, ok := c.h3.(interface{ FlushMasqueCoalesce() error }); ok {
			if c.DownloadActive() || len(p) < TunnelWriteToBufLen {
				_ = f.FlushMasqueCoalesce()
			}
		}
		if n > 0 && !c.DownloadActive() && c.routeBidiDuplex {
			if qs := c.h3.QUICStream(); qs != nil {
				quic.MasqueWakeStreamSend(qs)
			}
		}
	}
	return n, err
}

// readFromH3Thin copies upload bytes to the CONNECT stream (route ReaderFrom / iperf params).
func (c *TunnelConn) readFromH3Thin(r io.Reader) (int64, error) {
	bp := tunnelWriteToBufPool.Get().(*[]byte)
	defer tunnelWriteToBufPool.Put(bp)
	buf := *bp
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	dl := c.writeDL
	if !dl.IsZero() {
		_ = c.h3.SetWriteDeadline(dl)
	}
	var total int64
	for {
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := c.h3.Write(buf[:nr])
			if nw > 0 {
				c.noteUploadTrafficStarted()
				total += int64(nw)
				if c.routeBidiDuplex && c.DownloadActive() {
					atomic.StoreInt32(&c.duplexUploadStarted, 1)
					if qs := c.h3.QUICStream(); qs != nil {
						quic.MasqueSetBidiDuplexUploadStarted(qs, true)
					}
				}
				if ew == nil {
					if f, ok := c.h3.(interface{ FlushMasqueCoalesce() error }); ok && nr < H3UploadFlushChunkBytes {
						_ = f.FlushMasqueCoalesce()
					}
					if c.DownloadActive() && nr < H3UploadFlushChunkBytes {
						c.scheduler.wakeAfterUpload()
					}
				}
			}
			if ew != nil {
				return total, ew
			}
			if nr != nw {
				return total, io.ErrShortWrite
			}
			if c.DownloadActive() {
				c.noteDuplexUploadTraffic()
			}
		}
		if er != nil {
			if er == io.EOF {
				return total, nil
			}
			return total, er
		}
	}
}

func (c *TunnelConn) writeH3DownloadToThin(w io.Writer) (int64, error) {
	c.beginDuplexDownload()
	c.stopDownloadDrain()
	defer c.endDuplexDownload()

	if wt, ok := c.h3.(io.WriterTo); ok {
		c.lockReadMuForWriteTo()
		c.applyH3ReadDeadlineLocked()
		err := c.ctx.Err()
		c.readMu.Unlock()
		if err != nil {
			return 0, err
		}
		n, werr := wt.WriteTo(w)
		if n > 0 {
			c.noteDownloadDelivered()
			c.scheduler.noteDownloadDelivery(int(n))
		}
		return n, werr
	}

	bp := tunnelWriteToBufPool.Get().(*[]byte)
	defer tunnelWriteToBufPool.Put(bp)
	c.lockReadMuForWriteTo()
	c.applyH3ReadDeadlineLocked()
	err := c.ctx.Err()
	c.readMu.Unlock()
	if err != nil {
		return 0, err
	}
	n, werr := io.CopyBuffer(w, &tunnelH3Reader{c: c}, *bp)
	if n > 0 {
		c.noteDownloadDelivered()
	}
	return n, werr
}

// tunnelH3Reader adapts h3.Read for io.CopyBuffer (Invisv stream parity).
type tunnelH3Reader struct{ c *TunnelConn }

func (r *tunnelH3Reader) Read(p []byte) (int, error) {
	r.c.activateDownloadReceiveOnRead()
	uploadStarved := false
	if qs := r.c.h3.QUICStream(); qs != nil {
		uploadStarved = quic.MasqueUploadSendStarved(qs)
	}
	p = r.c.scheduler.capDownloadRead(p, uploadStarved)
	if len(p) >= H3UploadFlushChunkBytes {
		r.c.scheduler.wakeUploadDuringDownload()
	}
	n, err := r.c.h3.Read(p)
	if n > 0 {
		r.c.scheduler.noteDownloadDelivery(n)
		if n < H3UploadFlushChunkBytes {
			r.c.scheduler.wakeUploadDuringDownload()
		}
	}
	return n, err
}

// connectStreamDownloadCloseTimeout bounds H3 response-body Close during tunnel teardown (H2 parity).
const connectStreamDownloadCloseTimeout = 2 * time.Second

// SetConnectStreamRequestCancel wires H3 CONNECT request-context teardown on tunnel close (H2 parity).
func (c *TunnelConn) SetConnectStreamRequestCancel(cancel context.CancelCauseFunc) {
	if c != nil {
		c.requestCancel = cancel
	}
}

func (c *TunnelConn) CloseWrite() error {
	if c == nil || c.h3 == nil {
		return nil
	}
	atomic.StoreInt32(&c.uploadEOFClosed, 1)
	// http3.Stream.Close shuts the CONNECT send half; response download may continue.
	return c.h3.Close()
}

func (c *TunnelConn) Close() error {
	if c == nil {
		return nil
	}
	if atomic.LoadInt32(&c.downloadActive) > 0 {
		// Upload EOF: route CM CloseWrite then Close while download WriteTo runs — half-close only.
		if atomic.LoadInt32(&c.uploadEOFClosed) != 0 {
			return c.CloseWrite()
		}
		// Relay abort / client reset: tear down immediately (H2O slot recycle; no ghost streams).
		var err error
		c.closeFullOnce.Do(func() {
			err = c.closeFull()
		})
		return err
	}
	var err error
	c.closeFullOnce.Do(func() {
		err = c.closeFull()
	})
	return err
}

func (c *TunnelConn) closeFull() error {
	c.stopDownloadDrain()
	c.cancel()
	// H2 parity (stream/conn paths.bidiTunnelConn.Close): detach request context before
	// QUIC body teardown so relay abort does not leave ghost CONNECT streams.
	c.requestCancelOnce.Do(func() {
		if c.requestCancel != nil {
			c.requestCancel(context.Canceled)
		}
	})
	var err error
	if c.h3 != nil {
		if qs := c.h3.QUICStream(); qs != nil {
			quic.MasqueSetBidiDownloadReceiveActive(qs, false)
			quic.MasqueSetBidiDuplexUploadStarted(qs, false)
		}
		h3 := c.h3
		cancelCode := quic.StreamErrorCode(http3.ErrCodeRequestCanceled)
		if atomic.LoadInt32(&c.uploadTrafficStarted) == 0 {
			// Idle CONNECT (dial+immediate close): graceful FIN on send half lets peer
			// complete relay and raise MAX_STREAMS (Invisv / quic-go parity).
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
				c.stopDownloadDrain()
				h3.CancelRead(cancelCode)
				c.markCloseDone()
			}
		}
	} else {
		c.markCloseDone()
	}
	return err
}

func (c *TunnelConn) LocalAddr() net.Addr {
	if c != nil && c.local != nil {
		return c.local
	}
	return &net.TCPAddr{}
}

func (c *TunnelConn) RemoteAddr() net.Addr {
	if c != nil && c.remote != nil {
		return c.remote
	}
	return &net.TCPAddr{}
}

func (c *TunnelConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}

func (c *TunnelConn) SetReadDeadline(t time.Time) error {
	if c == nil {
		return nil
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
		return nil
	}
	c.writeMu.Lock()
	c.writeDL = t
	c.writeMu.Unlock()
	if c.h3 != nil {
		return c.h3.SetWriteDeadline(t)
	}
	return ErrDeadlineUnsupported
}

// RouteConnectionCopyWriterTo opts into route bulk download via io.WriterTo (sing-box).
func (*TunnelConn) RouteConnectionCopyWriterTo() {}

// RouteConnectionCopyReaderFrom opts into route bulk upload via io.ReaderFrom (sing-box).
func (*TunnelConn) RouteConnectionCopyReaderFrom() {}

var (
	_ io.WriterTo                     = (*TunnelConn)(nil)
	_ io.ReaderFrom                   = (*TunnelConn)(nil)
	_ C.RouteConnectionCopyWriterTo   = (*TunnelConn)(nil)
	_ C.RouteConnectionCopyReaderFrom = (*TunnelConn)(nil)
	_ C.RouteConnectionCopyDuplex     = (*TunnelConn)(nil)
)

// MarkConnectionCopyDuplex opts route CM out of upload-only download drain (prod TUN/SOCKS).
func (c *TunnelConn) MarkConnectionCopyDuplex() {
	if c != nil {
		c.routeBidiDuplex = true
	}
}

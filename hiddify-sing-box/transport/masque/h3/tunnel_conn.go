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

const tunnelWriteToBufLen = 256 * 1024

// TunnelWriteToBufLen reports the prod route WriteTo drain buffer (256 KiB anchor).
func TunnelWriteToBufLen() int { return tunnelWriteToBufLen }

var tunnelWriteToBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, tunnelWriteToBufLen)
		return &b
	},
}

// TunnelConn is a full-duplex TCP shim over one HTTP/3 CONNECT stream (RFC 9114 tunneled TCP).
// Default: Read/Write on *http3.Stream. Optional pipe upload when MASQUE_*_PIPE_UPLOAD=1.
type TunnelConn struct {
	h3     h3ConnectStream
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

	downloadActive      int32 // WriteTo in progress — upload wake for iperf -R duplex
	downloadDelivered   int32 // WriteTo delivered ≥1 response byte — true duplex interleave
	duplexUploadStarted int32 // concurrent upload Write while WriteTo active
	drainOnce           sync.Once
	drainStopped        int32 // background download discard during upload-only (H3 bidi drain)
	downloadReceiveOnce sync.Once
	downloadDeliveryPending int32 // batched WriteTo delivery wake (256 KiB)
	routeBidiDuplex       bool  // route pairs upload Write with concurrent download WriteTo — no auto drain
	bootstrapUploadDone   int32 // one-shot upload DATA before download drain (H2 parity)
	uploadTrafficStarted  int32 // client upload bytes hit the wire before WriteTo bootstrap (real iperf3 cookie)

	bidiWakeSink BidiWakeSink

	connectStreamRole ConnectStreamRole
}

// TunnelConnParams configures a TunnelConn over HTTP/3 CONNECT.
type TunnelConnParams struct {
	H3Stream     h3ConnectStream
	Reader       io.ReadCloser
	Writer       io.WriteCloser
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
		reader:            p.Reader,
		writer:            p.Writer,
		ctx:               ctx,
		cancel:            cancel,
		local:             p.Local,
		remote:            p.Remote,
		bidiWakeSink:      p.BidiWakeSink,
		routeBidiDuplex:   p.RouteBidiDuplex,
		connectStreamRole: normalizeConnectStreamRole(p.ConnectStreamLeg),
	}
	return conn
}

// UsesH3Stream reports whether upload/download share one *http3.Stream.
func (c *TunnelConn) UsesH3Stream() bool {
	return c != nil && c.h3 != nil
}

func (c *TunnelConn) stopDownloadDrain() {
	if atomic.SwapInt32(&c.drainStopped, 1) == 1 {
		return
	}
	// Unblock runDownloadDrain if it holds readMu in a blocking h3.Read (WriteTo needs the lock).
	if c.h3 != nil {
		_ = c.h3.SetReadDeadline(time.Now())
	}
}

// applyH3ReadDeadlineLocked sets or clears the h3 read deadline under readMu.
// stopDownloadDrain pokes time.Now(); route WriteTo must clear it when readDL is open-ended.
func (c *TunnelConn) applyH3ReadDeadlineLocked() {
	if c == nil || c.h3 == nil {
		return
	}
	if !c.readDL.IsZero() {
		_ = c.h3.SetReadDeadline(c.readDL)
	} else {
		_ = c.h3.SetReadDeadline(time.Time{})
	}
}

func (c *TunnelConn) maybeStartDownloadDrain() {
	if !H3BidiDownloadDrainEnabled() || c == nil || c.h3 == nil {
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
	const drainPollInterval = 50 * time.Millisecond
	buf := make([]byte, 32*1024)
	for {
		if err := c.ctx.Err(); err != nil {
			return
		}
		if atomic.LoadInt32(&c.drainStopped) > 0 || c.DownloadActive() {
			return
		}
		c.readMu.Lock()
		if atomic.LoadInt32(&c.drainStopped) > 0 || c.DownloadActive() {
			c.readMu.Unlock()
			return
		}
		dl := c.readDL
		if !dl.IsZero() {
			_ = c.h3.SetReadDeadline(dl)
		} else {
			_ = c.h3.SetReadDeadline(time.Now().Add(drainPollInterval))
		}
		n, err := c.h3.Read(buf)
		if dl.IsZero() {
			_ = c.h3.SetReadDeadline(time.Time{})
		}
		c.readMu.Unlock()
		if n > 0 {
			continue
		}
		if err != nil {
			if dl.IsZero() {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
			}
			return
		}
	}
}

func (c *TunnelConn) Read(p []byte) (int, error) {
	if c == nil {
		return 0, io.EOF
	}
	if c.h3 != nil {
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
			c.noteDownloadDeliveryWake(n)
		}
		return n, err
	}
	if c.reader == nil {
		return 0, io.EOF
	}
	c.stopDownloadDrain()
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

func (c *TunnelConn) Write(p []byte) (int, error) {
	if c == nil {
		return 0, io.ErrClosedPipe
	}
	if len(p) > 0 {
		atomic.StoreInt32(&c.uploadTrafficStarted, 1)
		if c.h3 != nil {
			if qs := c.h3.QUICStream(); qs != nil {
				quic.MasqueSetConcurrentUploadPending(qs, true)
			}
		}
	}
	if c.h3 != nil {
		c.maybeStartDownloadDrainOnUpload()
		n, err := c.writeH3Thin(p)
		if err != nil {
			err = errors.Join(ErrTunnelConnFailed, err)
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
	n, err := writeChunked(c.writer, p, H3UploadFlushPolicy().ChunkBytes)
	if err != nil {
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	return n, err
}

func (c *TunnelConn) ReadFrom(r io.Reader) (int64, error) {
	if c.h3 != nil {
		c.maybeStartDownloadDrainOnUpload()
		n, err := c.readFromH3Thin(r)
		if err != nil {
			err = errors.Join(ErrTunnelConnFailed, err)
		}
		return n, err
	}
	if c.writer == nil {
		return 0, io.ErrClosedPipe
	}
	n, err := copyChunked(c.writer, r, H3UploadFlushPolicy().ChunkBytes)
	if err != nil {
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	return n, err
}

func (c *TunnelConn) WriteTo(w io.Writer) (int64, error) {
	if c.h3 != nil {
		n, err := c.writeH3DownloadToThin(w)
		if err != nil {
			err = errors.Join(ErrTunnelConnFailed, err)
		}
		return n, err
	}
	if c.reader == nil {
		return 0, io.EOF
	}
	return io.Copy(w, c.reader)
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
	chunkBytes := H3UploadChunkBytes(c.DownloadActive(), c.DownloadDelivered(), atomic.LoadInt32(&c.duplexUploadStarted) != 0)
	var n int
	var err error
	if c.DownloadActive() && len(p) > chunkBytes {
		n, err = writeChunkedWake(c.h3, p, chunkBytes, func(wrote int) {
			if wrote > 0 && c.DownloadActive() {
				if f, ok := c.h3.(interface{ FlushMasqueCoalesce() error }); ok {
					_ = f.FlushMasqueCoalesce()
				}
				c.wakeBidiSendAfterUpload()
			}
		})
	} else {
		n, err = c.h3.Write(p)
		if err == nil && c.DownloadActive() {
			c.wakeBidiSendAfterUpload()
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
			if c.DownloadActive() || len(p) < tunnelWriteToBufLen {
				_ = f.FlushMasqueCoalesce()
			}
		}
		if n > 0 && !c.DownloadActive() && c.routeBidiDuplex && c.h3 != nil {
			if qs := c.h3.QUICStream(); qs != nil {
				quic.MasqueWakeStreamSend(qs)
			}
		}
	}
	return n, err
}

const h3HandshakeUploadFlushBytes = 64 * 1024

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
				if c.routeBidiDuplex && c.DownloadActive() && c.h3 != nil {
					atomic.StoreInt32(&c.duplexUploadStarted, 1)
					if qs := c.h3.QUICStream(); qs != nil {
						quic.MasqueSetBidiDuplexUploadStarted(qs, true)
					}
				}
				if ew == nil {
					if f, ok := c.h3.(interface{ FlushMasqueCoalesce() error }); ok && nr < h3HandshakeUploadFlushBytes {
						_ = f.FlushMasqueCoalesce()
					}
					if c.DownloadActive() && nr < h3HandshakeUploadFlushBytes {
						c.wakeBidiSendAfterUpload()
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
	c.stopDownloadDrain()
	c.beginDuplexDownload()
	defer c.endDuplexDownload()

	if wt, ok := c.h3.(io.WriterTo); ok {
		c.readMu.Lock()
		c.applyH3ReadDeadlineLocked()
		err := c.ctx.Err()
		c.readMu.Unlock()
		if err != nil {
			return 0, err
		}
		n, werr := wt.WriteTo(w)
		if n > 0 {
			c.noteDownloadDelivered()
			c.noteDownloadDeliveryWake(int(n))
		}
		return n, werr
	}

	bp := tunnelWriteToBufPool.Get().(*[]byte)
	defer tunnelWriteToBufPool.Put(bp)
	c.readMu.Lock()
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

const duplexStarvedDownloadReadCap = 16 * 1024

func (r *tunnelH3Reader) Read(p []byte) (int, error) {
	r.c.activateDownloadReceiveOnRead()
	if qs := r.c.h3.QUICStream(); qs != nil && quic.MasqueUploadSendStarved(qs) && len(p) > duplexStarvedDownloadReadCap {
		p = p[:duplexStarvedDownloadReadCap]
	}
	if len(p) >= h3HandshakeUploadFlushBytes {
		r.c.wakeH3BidiUploadDuringDownload()
	}
	n, err := r.c.h3.Read(p)
	if n > 0 {
		r.c.noteDownloadDeliveryWake(n)
		if n < h3HandshakeUploadFlushBytes {
			r.c.wakeH3BidiUploadDuringDownload()
		}
	}
	return n, err
}

func (c *TunnelConn) Close() error {
	c.stopDownloadDrain()
	c.cancel()
	var err error
	if c.h3 != nil {
		if qs := c.h3.QUICStream(); qs != nil {
			quic.MasqueSetBidiDownloadReceiveActive(qs, false)
			quic.MasqueSetBidiDuplexUploadStarted(qs, false)
		}
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

func (c *TunnelConn) SetWriteDeadline(t time.Time) error {
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
func (*TunnelConn) RouteConnectionCopyWriterTo() {}

// RouteConnectionCopyReaderFrom opts into route bulk upload via io.ReaderFrom (sing-box).
func (*TunnelConn) RouteConnectionCopyReaderFrom() {}

var (
	_ io.WriterTo                     = (*TunnelConn)(nil)
	_ io.ReaderFrom                   = (*TunnelConn)(nil)
	_ C.RouteConnectionCopyWriterTo   = (*TunnelConn)(nil)
	_ C.RouteConnectionCopyReaderFrom = (*TunnelConn)(nil)
)

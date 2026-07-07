package h3

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	C "github.com/sagernet/sing-box/constant"
)

// DualTunnelConn is a P2 composite net.Conn: download and upload use separate CONNECT-stream legs
// on one QUIC connection (distinct h3_stream tunnels per leg).
type DualTunnelConn struct {
	download     net.Conn
	upload       net.Conn
	uploadDial   UploadLegDial
	uploadOnce   sync.Once
	uploadDialErr error
	ctx          context.Context
	cancel       context.CancelFunc
	local        net.Addr
	remote       net.Addr
	closeMu      sync.Mutex
	closed       bool
}

// UploadLegDial opens the upload CONNECT-stream leg (lazy on first Write/ReadFrom).
type UploadLegDial func() (net.Conn, error)

// DualTunnelConnParams configures a P2 dual-leg tunnel.
type DualTunnelConnParams struct {
	Download   net.Conn
	Upload     net.Conn // optional; when nil, UploadDial is used on first upload I/O
	Ctx        context.Context
	Local      net.Addr
	Remote     net.Addr
	UploadDial UploadLegDial
}

// NewDualTunnelConn builds a composite tunnel from separate download (read/WriteTo) and upload (write/ReadFrom) legs.
func NewDualTunnelConn(p DualTunnelConnParams) *DualTunnelConn {
	dl, ul := p.Download, p.Upload
	ctx := p.Ctx
	var cancel context.CancelFunc
	if ctx == nil {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	local, remote := p.Local, p.Remote
	if local == nil && dl != nil {
		local = dl.LocalAddr()
	}
	if remote == nil && dl != nil {
		remote = dl.RemoteAddr()
	}
	return &DualTunnelConn{
		download:   dl,
		upload:     ul,
		uploadDial: p.UploadDial,
		ctx:        ctx,
		cancel:     cancel,
		local:      local,
		remote:     remote,
	}
}

// SetUploadDial replaces the lazy upload-leg dialer.
func (c *DualTunnelConn) SetUploadDial(d UploadLegDial) {
	if c != nil {
		c.uploadDial = d
	}
}

func (c *DualTunnelConn) ensureUploadLeg() error {
	if c == nil {
		return io.ErrClosedPipe
	}
	if c.upload != nil {
		return nil
	}
	if c.uploadDial == nil {
		return io.ErrClosedPipe
	}
	c.uploadOnce.Do(func() {
		ul, err := c.uploadDial()
		if err != nil {
			c.uploadDialErr = err
			return
		}
		c.upload = ul
	})
	return c.uploadDialErr
}

// UsesDualConnect reports P2 dual-leg mode (always true for this type).
func (*DualTunnelConn) UsesDualConnect() bool { return true }

// DownloadLeg returns the read/WriteTo CONNECT-stream leg.
func (c *DualTunnelConn) DownloadLeg() net.Conn {
	if c == nil {
		return nil
	}
	return c.download
}

// UploadLeg returns the write/ReadFrom CONNECT-stream leg.
func (c *DualTunnelConn) UploadLeg() net.Conn {
	if c == nil {
		return nil
	}
	return c.upload
}

func (c *DualTunnelConn) TunnelPolicySnapshot() TunnelPolicySnapshot {
	return TunnelPolicySnapshot{
		Mode:            ConnectStreamModeSplitLegs,
		RouteBidiDuplex: false,
		UsesH3Stream:    true,
		SchedPolicy:     ProdConnectStreamSchedPolicy(),
	}
}

func (c *DualTunnelConn) Read(p []byte) (int, error) {
	if c == nil || c.download == nil {
		return 0, io.EOF
	}
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.download.Read(p)
	if err != nil {
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	return n, err
}

func (c *DualTunnelConn) Write(p []byte) (int, error) {
	if c == nil {
		return 0, io.ErrClosedPipe
	}
	if err := c.ensureUploadLeg(); err != nil {
		return 0, err
	}
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.upload.Write(p)
	if err != nil {
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	return n, err
}

func (c *DualTunnelConn) ReadFrom(r io.Reader) (int64, error) {
	if c == nil {
		return 0, io.ErrClosedPipe
	}
	// Route always starts an upload goroutine; defer second CONNECT until the local side sends data.
	if c.upload == nil && c.uploadDial != nil {
		buf := make([]byte, 32*1024)
		n, err := r.Read(buf)
		if n == 0 {
			if err != nil {
				if errors.Is(err, io.EOF) {
					return 0, nil
				}
				return 0, err
			}
			return 0, nil
		}
		if dialErr := c.ensureUploadLeg(); dialErr != nil {
			return 0, dialErr
		}
		wrote, werr := c.upload.Write(buf[:n])
		if werr != nil {
			return int64(wrote), errors.Join(ErrTunnelConnFailed, werr)
		}
		if wrote < n {
			return int64(wrote), io.ErrShortWrite
		}
		rest, cerr := io.Copy(c.upload, r)
		return int64(wrote) + rest, cerr
	}
	if err := c.ensureUploadLeg(); err != nil {
		return 0, err
	}
	if rf, ok := c.upload.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(r)
		if err != nil && !errors.Is(err, io.EOF) {
			err = errors.Join(ErrTunnelConnFailed, err)
		}
		return n, err
	}
	n, err := io.Copy(c.upload, r)
	if err != nil && !errors.Is(err, io.EOF) {
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	return n, err
}

func (c *DualTunnelConn) WriteTo(w io.Writer) (int64, error) {
	if c == nil || c.download == nil {
		return 0, io.EOF
	}
	if wt, ok := c.download.(io.WriterTo); ok {
		n, err := wt.WriteTo(w)
		if err != nil && !errors.Is(err, io.EOF) {
			err = errors.Join(ErrTunnelConnFailed, err)
		}
		return n, err
	}
	n, err := io.Copy(w, c.download)
	if err != nil && !errors.Is(err, io.EOF) {
		err = errors.Join(ErrTunnelConnFailed, err)
	}
	return n, err
}

func (c *DualTunnelConn) Close() error {
	if c == nil {
		return nil
	}
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.cancel()
	var err error
	if c.download != nil {
		err = errors.Join(err, c.download.Close())
	}
	if c.upload != nil {
		err = errors.Join(err, c.upload.Close())
	}
	return err
}

func (c *DualTunnelConn) LocalAddr() net.Addr {
	if c != nil && c.local != nil {
		return c.local
	}
	return &net.TCPAddr{}
}

func (c *DualTunnelConn) RemoteAddr() net.Addr {
	if c != nil && c.remote != nil {
		return c.remote
	}
	return &net.TCPAddr{}
}

func (c *DualTunnelConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}

func (c *DualTunnelConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.download == nil {
		return ErrDeadlineUnsupported
	}
	return c.download.SetReadDeadline(t)
}

func (c *DualTunnelConn) SetWriteDeadline(t time.Time) error {
	if c == nil {
		return ErrDeadlineUnsupported
	}
	if c.upload == nil {
		return nil
	}
	return c.upload.SetWriteDeadline(t)
}

// RouteConnectionCopyWriterTo opts into route bulk download via io.WriterTo (sing-box).
func (*DualTunnelConn) RouteConnectionCopyWriterTo() {}

// RouteConnectionCopyReaderFrom opts into route bulk upload via io.ReaderFrom (sing-box).
func (*DualTunnelConn) RouteConnectionCopyReaderFrom() {}

var (
	_ io.WriterTo                     = (*DualTunnelConn)(nil)
	_ io.ReaderFrom                   = (*DualTunnelConn)(nil)
	_ C.RouteConnectionCopyWriterTo   = (*DualTunnelConn)(nil)
	_ C.RouteConnectionCopyReaderFrom = (*DualTunnelConn)(nil)
	_ TunnelFacade                    = (*DualTunnelConn)(nil)
)

package asymconn

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp/split"
)

// PacketConn splits C2S (upload leg) and S2C (download leg) across two CONNECT-UDP streams (H2/H3 asymmetric dial).
type PacketConn struct {
	download   net.PacketConn
	upload     net.PacketConn
	localAddr  net.Addr
	remoteAddr net.Addr

	closed    atomic.Bool
	onClose   func()
	closeOnce sync.Once

	deadlines split.ConnDeadlines
}

// NewPacketConn wires download ReadFrom with upload WriteTo (Invisv blocking shape; sync upload leg).
func NewPacketConn(download, upload net.PacketConn, localAddr, remoteAddr net.Addr, onClose func()) *PacketConn {
	if download == nil || upload == nil {
		panic("connectudp/asymconn: NewPacketConn requires download and upload conns")
	}
	if localAddr == nil {
		localAddr = download.LocalAddr()
	}
	if remoteAddr == nil {
		if ra, ok := download.(interface{ RemoteAddr() net.Addr }); ok {
			remoteAddr = ra.RemoteAddr()
		}
		if remoteAddr == nil {
			remoteAddr = localAddr
		}
	}
	return &PacketConn{
		download:   download,
		upload:     upload,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		onClose:    onClose,
	}
}

func (c *PacketConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *PacketConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *PacketConn) SetDeadline(t time.Time) error {
	c.deadlines.SetDeadline(t)
	_ = c.download.SetDeadline(t)
	_ = c.upload.SetWriteDeadline(t)
	return nil
}

func (c *PacketConn) SetReadDeadline(t time.Time) error {
	c.deadlines.SetReadDeadline(t)
	return c.download.SetReadDeadline(t)
}

func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	c.deadlines.SetWriteDeadline(t)
	return c.upload.SetWriteDeadline(t)
}

func (c *PacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		_ = c.download.Close()
		_ = c.upload.Close()
		c.FlushC2SWrites()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}

func (c *PacketConn) IsClosed() bool { return c.closed.Load() }

func (c *PacketConn) FlushC2SWrites() {
	if f, ok := c.download.(interface{ FlushC2SWrites() }); ok {
		f.FlushC2SWrites()
	}
	if f, ok := c.upload.(interface{ FlushC2SWrites() }); ok {
		f.FlushC2SWrites()
	}
}

func (c *PacketConn) flushUploadPendingBeforeRead() {
	if f, ok := c.upload.(interface{ FlushC2SWrites() }); ok {
		f.FlushC2SWrites()
	}
}

func (c *PacketConn) AwaitUploadDrain(timeout time.Duration) error {
	if c == nil || c.closed.Load() {
		return nil
	}
	if d, ok := c.upload.(interface {
		AwaitUploadDrain(time.Duration) error
	}); ok {
		return d.AwaitUploadDrain(timeout)
	}
	return nil
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if c.deadlines.WriteTimeoutExceeded() {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := c.upload.WriteTo(p, addr)
	if err != nil {
		_ = c.Close()
		return n, err
	}
	return n, nil
}

func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	if v := c.deadlines.Read.Load(); v != 0 && time.Now().UnixNano() > v {
		return 0, nil, os.ErrDeadlineExceeded
	}
	c.flushUploadPendingBeforeRead()
	return c.download.ReadFrom(p)
}

func (c *PacketConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

func (c *PacketConn) Write(p []byte) (int, error) {
	return c.WriteTo(p, c.remoteAddr)
}

package h2

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp/split"
)

// AsymmetricPacketConn splits C2S (upload pool) and S2C (download-primary) across CONNECT-UDP legs.
type AsymmetricPacketConn struct {
	download  net.PacketConn
	uploads   []net.PacketConn
	localAddr net.Addr
	remoteAddr net.Addr

	uploadCh    chan shardedUploadJob
	uploadSlots chan struct{} // bounds async in-flight vs uploadPipe backpressure
	uploadWG    sync.WaitGroup
	inFlight    sync.WaitGroup
	firstWErr atomic.Value

	writesBeforeRead atomic.Uint32
	closed           atomic.Bool
	onClose          func()
	closeOnce        sync.Once
	uploadClose      chan struct{} // closed before uploadCh — unblocks WriteTo on selector interrupt

	deadlines split.ConnDeadlines
}

// NewAsymmetricPacketConn wires download-primary ReadFrom with upload-pool WriteTo.
func NewAsymmetricPacketConn(download net.PacketConn, uploads []net.PacketConn, localAddr, remoteAddr net.Addr, onClose func()) *AsymmetricPacketConn {
	if download == nil {
		panic("h2: NewAsymmetricPacketConn requires download conn")
	}
	if len(uploads) == 0 {
		panic("h2: NewAsymmetricPacketConn requires >=1 upload conn")
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
	uploadChCap := len(uploads) * 4
	if uploadChCap < 4 {
		uploadChCap = 4
	}
	c := &AsymmetricPacketConn{
		download:    download,
		uploads:     uploads,
		localAddr:   localAddr,
		remoteAddr:  remoteAddr,
		onClose:     onClose,
		uploadCh:    make(chan shardedUploadJob, uploadChCap),
		uploadSlots: make(chan struct{}, len(uploads)),
		uploadClose: make(chan struct{}),
	}
	for i := range uploads {
		conn := uploads[i]
		c.uploadWG.Add(1)
		go c.uploadWorker(conn)
	}
	return c
}

func (c *AsymmetricPacketConn) uploadWorker(conn net.PacketConn) {
	defer c.uploadWG.Done()
	for job := range c.uploadCh {
		n, err := conn.WriteTo(job.payload, job.addr)
		if job.pooled {
			releaseUploadPayload(job.payload)
		}
		if job.sync {
			job.done <- shardedWriteResult{n: n, err: err}
			continue
		}
		<-c.uploadSlots
		if err != nil {
			c.firstWErr.CompareAndSwap(nil, err)
			_ = c.Close()
		}
		c.inFlight.Done()
	}
}

func (c *AsymmetricPacketConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *AsymmetricPacketConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *AsymmetricPacketConn) SetDeadline(t time.Time) error {
	c.deadlines.SetDeadline(t)
	_ = c.download.SetDeadline(t)
	for _, conn := range c.uploads {
		_ = conn.SetWriteDeadline(t)
	}
	return nil
}

func (c *AsymmetricPacketConn) SetReadDeadline(t time.Time) error {
	c.deadlines.SetReadDeadline(t)
	return c.download.SetReadDeadline(t)
}

func (c *AsymmetricPacketConn) SetWriteDeadline(t time.Time) error {
	c.deadlines.SetWriteDeadline(t)
	for _, conn := range c.uploads {
		_ = conn.SetWriteDeadline(t)
	}
	return nil
}

func (c *AsymmetricPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.uploadClose)
		_ = c.download.Close()
		for _, conn := range c.uploads {
			_ = conn.Close()
		}
		close(c.uploadCh)
		c.uploadWG.Wait()
		c.inFlight.Wait()
		c.FlushC2SWrites()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}

func (c *AsymmetricPacketConn) abortUploadJob(job shardedUploadJob) {
	if job.pooled {
		releaseUploadPayload(job.payload)
	}
	if !job.sync {
		<-c.uploadSlots
		c.inFlight.Done()
	}
}

func (c *AsymmetricPacketConn) sendUploadJob(job shardedUploadJob) error {
	select {
	case c.uploadCh <- job:
		return nil
	case <-c.uploadClose:
		c.abortUploadJob(job)
		return net.ErrClosed
	}
}

func (c *AsymmetricPacketConn) FlushC2SWrites() {
	if f, ok := c.download.(interface{ FlushC2SWrites() }); ok {
		f.FlushC2SWrites()
	}
	for _, conn := range c.uploads {
		if f, ok := conn.(interface{ FlushC2SWrites() }); ok {
			f.FlushC2SWrites()
		}
	}
}

func (c *AsymmetricPacketConn) AwaitUploadDrain(timeout time.Duration) error {
	if c == nil || c.closed.Load() {
		return nil
	}
	done := make(chan struct{})
	go func() {
		c.inFlight.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		return os.ErrDeadlineExceeded
	}
	if err, _ := c.firstWErr.Load().(error); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	var firstErr error
	for _, conn := range c.uploads {
		rem := time.Until(deadline)
		if rem <= 0 {
			return os.ErrDeadlineExceeded
		}
		if d, ok := conn.(interface {
			AwaitUploadDrain(time.Duration) error
		}); ok {
			if err := d.AwaitUploadDrain(rem); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (c *AsymmetricPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if c.deadlines.WriteTimeoutExceeded() {
		return 0, os.ErrDeadlineExceeded
	}
	for _, conn := range c.uploads {
		if pc, ok := conn.(*PacketConn); ok {
			pc.markDuplexPeerActive()
		}
	}
	c.wakeDownloadPumpForUpload()
	if len(p) == 0 {
		for _, conn := range c.uploads {
			if _, err := conn.WriteTo(nil, addr); err != nil {
				_ = c.Close()
				return 0, err
			}
		}
		return 0, nil
	}
	if len(c.uploads) == 1 {
		return c.uploads[0].WriteTo(p, addr)
	}
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	payload := borrowUploadPayload(len(p))
	copy(payload, p)
	done := make(chan shardedWriteResult, 1)
	syncWrite := c.writesBeforeRead.Add(1) <= 4
	job := shardedUploadJob{payload: payload, addr: addr, sync: syncWrite, pooled: true, done: done}
	if !syncWrite {
		c.inFlight.Add(1)
		c.uploadSlots <- struct{}{}
	}
	if c.closed.Load() {
		if job.pooled {
			releaseUploadPayload(payload)
		}
		if !syncWrite {
			<-c.uploadSlots
			c.inFlight.Done()
		}
		return 0, net.ErrClosed
	}
	if err := c.sendUploadJob(job); err != nil {
		return 0, err
	}
	if syncWrite {
		res := <-done
		if res.err != nil {
			_ = c.Close()
			return res.n, res.err
		}
		return len(p), nil
	}
	return len(p), nil
}

func (c *AsymmetricPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	if v := c.deadlines.Read.Load(); v != 0 && time.Now().UnixNano() > v {
		return 0, nil, os.ErrDeadlineExceeded
	}
	n, addr, err := c.download.ReadFrom(p)
	if n > 0 {
		for _, conn := range c.uploads {
			if pc, ok := conn.(*PacketConn); ok {
				pc.markDuplexPeerActive()
			}
		}
	}
	return n, addr, err
}

func (c *AsymmetricPacketConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

func (c *AsymmetricPacketConn) Write(p []byte) (int, error) {
	return c.WriteTo(p, c.remoteAddr)
}

func (c *AsymmetricPacketConn) wakeDownloadPumpForUpload() {
	if pc, ok := c.download.(*PacketConn); ok && pc != nil && !pc.closed.Load() && pc.asyncDownlink {
		pc.ensureDownlinkPump()
	}
}

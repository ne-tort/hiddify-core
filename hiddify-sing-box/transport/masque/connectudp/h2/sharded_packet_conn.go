package h2

import (
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp/split"
)

type shardedDatagram struct {
	payload []byte
	addr    net.Addr
}

type shardedUploadJob struct {
	payload []byte
	addr    net.Addr
	sync    bool
	pooled  bool
	done    chan shardedWriteResult
}

type shardedWriteResult struct {
	n   int
	err error
}

// ShardedPacketConn fans upload across parallel H2 CONNECT-UDP streams (one TCP pool each).
type ShardedPacketConn struct {
	conns      []net.PacketConn
	localAddr  net.Addr
	remoteAddr net.Addr

	uploadCh chan shardedUploadJob
	uploadWG sync.WaitGroup
	inFlight sync.WaitGroup
	firstWErr atomic.Value

	readsSeen        atomic.Uint32
	writesBeforeRead atomic.Uint32

	readMu    sync.Mutex
	readReady sync.Cond
	readQueue []shardedDatagram
	readDone  int
	readErr   error
	closed    atomic.Bool
	onClose   func()

	uploadClose chan struct{} // closed before uploadCh — unblocks WriteTo on selector interrupt

	deadlines split.ConnDeadlines
	closeOnce sync.Once
}

// NewShardedPacketConn builds a multi-stream CONNECT-UDP client (>=2 conns).
func NewShardedPacketConn(conns []net.PacketConn, localAddr, remoteAddr net.Addr, onClose func()) *ShardedPacketConn {
	if len(conns) < 2 {
		panic("h2: NewShardedPacketConn requires >=2 conns")
	}
	if localAddr == nil {
		localAddr = conns[0].LocalAddr()
	}
	if remoteAddr == nil {
		remoteAddr = localAddr
	}
	c := &ShardedPacketConn{
		conns:       conns,
		localAddr:   localAddr,
		remoteAddr:  remoteAddr,
		onClose:     onClose,
		uploadCh:    make(chan shardedUploadJob, 512),
		uploadClose: make(chan struct{}),
	}
	c.readReady.L = &c.readMu
	for i := range conns {
		go c.runShardReader(conns[i])
		c.uploadWG.Add(1)
		go c.uploadWorker(conns[i])
	}
	return c
}

func (c *ShardedPacketConn) uploadWorker(conn net.PacketConn) {
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
		if err != nil {
			c.firstWErr.CompareAndSwap(nil, err)
			_ = c.Close()
		}
		c.inFlight.Done()
	}
}

func (c *ShardedPacketConn) runShardReader(conn net.PacketConn) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if c.closed.Load() {
			return
		}
		if err != nil {
			c.readMu.Lock()
			if c.closed.Load() {
				c.readMu.Unlock()
				return
			}
			if c.readErr == nil {
				c.readErr = err
			}
			c.readDone++
			if c.readDone >= len(c.conns) {
				c.readReady.Broadcast()
			}
			c.readMu.Unlock()
			return
		}
		if n == 0 {
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		if addr == nil {
			addr = c.remoteAddr
		}
		c.readMu.Lock()
		if c.closed.Load() {
			c.readMu.Unlock()
			return
		}
		c.readQueue = append(c.readQueue, shardedDatagram{payload: payload, addr: addr})
		c.readReady.Broadcast()
		c.readMu.Unlock()
	}
}

func (c *ShardedPacketConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *ShardedPacketConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *ShardedPacketConn) SetDeadline(t time.Time) error {
	c.deadlines.SetDeadline(t)
	for _, conn := range c.conns {
		_ = conn.SetWriteDeadline(t)
	}
	c.readReady.Broadcast()
	return nil
}

func (c *ShardedPacketConn) SetReadDeadline(t time.Time) error {
	c.deadlines.SetReadDeadline(t)
	c.readReady.Broadcast()
	return nil
}

func (c *ShardedPacketConn) SetWriteDeadline(t time.Time) error {
	c.deadlines.SetWriteDeadline(t)
	for _, conn := range c.conns {
		_ = conn.SetWriteDeadline(t)
	}
	return nil
}

func (c *ShardedPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.uploadClose)
		c.readReady.Broadcast()
		for _, conn := range c.conns {
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

func (c *ShardedPacketConn) abortUploadJob(job shardedUploadJob) {
	if job.pooled {
		releaseUploadPayload(job.payload)
	}
	if !job.sync {
		c.inFlight.Done()
	}
}

func (c *ShardedPacketConn) sendUploadJob(job shardedUploadJob) error {
	select {
	case c.uploadCh <- job:
		return nil
	case <-c.uploadClose:
		c.abortUploadJob(job)
		return net.ErrClosed
	}
}

func (c *ShardedPacketConn) FlushC2SWrites() {
	for _, conn := range c.conns {
		if f, ok := conn.(interface{ FlushC2SWrites() }); ok {
			f.FlushC2SWrites()
		}
	}
}

func (c *ShardedPacketConn) AwaitUploadDrain(timeout time.Duration) error {
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
	for _, conn := range c.conns {
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

func (c *ShardedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if c.deadlines.WriteTimeoutExceeded() {
		return 0, os.ErrDeadlineExceeded
	}
	if len(p) == 0 {
		for _, conn := range c.conns {
			if _, err := conn.WriteTo(nil, addr); err != nil {
				_ = c.Close()
				return 0, err
			}
		}
		return 0, nil
	}
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	payload := borrowUploadPayload(len(p))
	copy(payload, p)
	done := make(chan shardedWriteResult, 1)
	syncWrite := c.readsSeen.Load() == 0 && c.writesBeforeRead.Add(1) <= 4
	job := shardedUploadJob{payload: payload, addr: addr, sync: syncWrite, pooled: true, done: done}
	if !syncWrite {
		c.inFlight.Add(1)
	}
	if c.closed.Load() {
		if job.pooled {
			releaseUploadPayload(payload)
		}
		if !syncWrite {
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

func (c *ShardedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	var deadlineTimer *time.Timer
	var deadlineC <-chan time.Time
	if v := c.deadlines.Read.Load(); v != 0 {
		if time.Now().UnixNano() > v {
			return 0, nil, os.ErrDeadlineExceeded
		}
		deadlineTimer = time.NewTimer(time.Until(time.Unix(0, v)))
		deadlineC = deadlineTimer.C
		defer deadlineTimer.Stop()
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if len(c.readQueue) > 0 {
			dg := c.readQueue[0]
			c.readQueue = c.readQueue[1:]
			if len(c.readQueue) == 0 {
				c.readQueue = nil
			}
			c.readsSeen.Add(1)
			return copy(p, dg.payload), dg.addr, nil
		}
		if c.readErr != nil && c.readDone >= len(c.conns) {
			if errors.Is(c.readErr, net.ErrClosed) {
				return 0, nil, net.ErrClosed
			}
			return 0, nil, c.readErr
		}
		if c.closed.Load() {
			return 0, nil, net.ErrClosed
		}
		if deadlineC != nil {
			select {
			case <-deadlineC:
				return 0, nil, os.ErrDeadlineExceeded
			default:
				c.readReady.Wait()
			}
			continue
		}
		c.readReady.Wait()
	}
}

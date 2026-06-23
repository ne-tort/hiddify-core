package masque

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

type masqueAddr struct{ string }

func (m masqueAddr) Network() string { return "connect-udp" }
func (m masqueAddr) String() string  { return m.string }

var _ net.Addr = masqueAddr{}

// Backing slices for CONNECT-UDP WriteTo: quic/http3 sends sync-copy into its own pooled
// QUIC datagram buffer, so reusing scratch here avoids an allocation per egress datagram under load.
var proxiedConnWriteBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 2048)
		return &b
	},
}

type http3Stream interface {
	io.ReadWriteCloser
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
	CancelRead(quic.StreamErrorCode)
}

// tryDrainHTTPDatagrams exposes a non-blocking datagram dequeue when using quic-go's HTTP/3 implementation.
type tryDrainHTTPDatagrams interface {
	TryReceiveDatagram() ([]byte, bool)
}

const (
	proxiedConnPrefetchMax               = 512
	proxiedConnPrefetchMask              = proxiedConnPrefetchMax - 1
	proxiedConnExpiredPrefetchDropBudget = 64
	proxiedConnPrefetchDrainProbeMaxSkip = 64
	proxiedConnWriteHTTPBatchFlush       = 8
	proxiedConnWriteQueueCap             = 2048
	proxiedConnWriteCloseDrainWait       = 2 * time.Second
)

type proxiedConnDatagramFlushSender interface {
	SendDatagramNoWake([]byte) error
	FlushProxiedIPDatagramSend()
}

// Bounds for draining ignored capsules on the HTTP/3 CONNECT-UDP request stream (skipCapsules).
const (
	skipCapsuleDatagramMaxPayload    = 1500 + 128
	skipCapsuleNondatagramMaxPayload = 65536
	capsuleTypeDatagram              = http3.CapsuleType(0)
)

var (
	_ http3Stream = &http3.Stream{}
	_ http3Stream = &http3.RequestStream{}
)

type proxiedConn struct {
	str        http3Stream
	drain      tryDrainHTTPDatagrams
	localAddr  net.Addr
	remoteAddr net.Addr

	closed   atomic.Bool
	readDone chan struct{}

	pumpOnce       sync.Once
	prefetchNotify chan struct{}
	pumpCtx        context.Context
	pumpCancel     context.CancelFunc

	prefetchMu          sync.Mutex
	prefetchSlots       [][]byte
	prefetchHead        int
	prefetchCount       int
	prefetchCountAtomic atomic.Int32
	prefetchGate        adaptiveTryDrainGate

	writeFlushSender  proxiedConnDatagramFlushSender
	writeMu           sync.Mutex
	pendingWriteBatch int
	writeOnce         sync.Once
	writeCloseOnce    sync.Once
	writeCh           chan []byte
	writeDone         chan struct{}
	writeErr          atomic.Pointer[error]

	deadlineMx        sync.Mutex
	readCtx           context.Context
	readCtxCancel     context.CancelFunc
	deadline          time.Time
	readDeadlineTimer *time.Timer
}

var _ net.PacketConn = &proxiedConn{}

// ErrICMPPortUnreachable is returned from ReadFrom when the relay delivered ICMP
// destination-unreachable as an empty CONNECT-UDP payload (context id 0, zero UDP bytes).
var ErrICMPPortUnreachable = errors.New("masque connect-udp icmp port unreachable")

func newProxiedConn(str http3Stream, local, remote net.Addr) *proxiedConn {
	c := &proxiedConn{
		str:           str,
		localAddr:     local,
		remoteAddr:    remote,
		readDone:      make(chan struct{}),
		prefetchSlots: make([][]byte, proxiedConnPrefetchMax),
	}
	if dr, ok := str.(tryDrainHTTPDatagrams); ok {
		c.drain = dr
	}
	if fs, ok := str.(proxiedConnDatagramFlushSender); ok {
		c.writeFlushSender = fs
	}
	c.prefetchNotify = make(chan struct{}, 256)
	c.pumpCtx, c.pumpCancel = context.WithCancel(context.Background())
	c.readCtx, c.readCtxCancel = context.WithCancel(context.Background())
	c.startDatagramPump()
	go func() {
		defer close(c.readDone)
		if err := skipCapsules(quicvarint.NewReader(str)); err != nil && !errors.Is(err, io.EOF) && !c.closed.Load() {
			log.Printf("reading from request stream failed: %v", err)
		}
		str.Close()
	}()
	return c
}

func (c *proxiedConn) startDatagramPump() {
	c.pumpOnce.Do(func() {
		go c.pumpH3Datagrams()
	})
}

func (c *proxiedConn) pumpH3Datagrams() {
	for {
		if c.closed.Load() {
			return
		}
		if c.drainTryReceiveIntoPrefetch() > 0 {
			continue
		}
		if c.prefetchCountAtomic.Load() >= proxiedConnPrefetchMax {
			select {
			case <-c.pumpCtx.Done():
				return
			case <-c.prefetchNotify:
			case <-time.After(10 * time.Microsecond):
			}
			continue
		}
		data, err := c.str.ReceiveDatagram(c.pumpCtx)
		if err != nil {
			if c.closed.Load() || errors.Is(err, context.Canceled) {
				return
			}
			if errors.Is(err, io.EOF) {
				return
			}
			continue
		}
		if !c.enqueuePrefetchedRaw(data) {
			continue
		}
		c.drainTryReceiveIntoPrefetch()
	}
}

func (c *proxiedConn) drainTryReceiveIntoPrefetch() int {
	return c.drainTryReceiveBatchIntoPrefetch()
}

func (c *proxiedConn) drainTryReceiveBatchIntoPrefetch() int {
	total := 0
	for c.prefetchCountAtomic.Load() < proxiedConnPrefetchMax {
		n := c.drainOneTryReceiveBatch()
		if n == 0 {
			break
		}
		total += n
	}
	return total
}

func (c *proxiedConn) drainOneTryReceiveBatch() int {
	if c.drain == nil {
		return 0
	}
	space := proxiedConnPrefetchMax - int(c.prefetchCountAtomic.Load())
	if space <= 0 {
		return 0
	}
	const maxBatch = 32
	var batch [maxBatch][]byte
	n := 0
	for n < space && n < maxBatch {
		raw, ok := c.drain.TryReceiveDatagram()
		if !ok {
			break
		}
		batch[n] = raw
		n++
	}
	if n == 0 {
		return 0
	}
	c.prefetchMu.Lock()
	drained := 0
	for i := 0; i < n && c.prefetchCount < proxiedConnPrefetchMax; i++ {
		tail := (c.prefetchHead + c.prefetchCount) & proxiedConnPrefetchMask
		c.prefetchSlots[tail] = batch[i]
		c.prefetchCount++
		drained++
	}
	c.prefetchCountAtomic.Store(int32(c.prefetchCount))
	c.prefetchMu.Unlock()
	if drained > 0 {
		c.signalPrefetchReady()
	}
	return drained
}

func (c *proxiedConn) signalPrefetchReady() {
	select {
	case c.prefetchNotify <- struct{}{}:
	default:
	}
}

func (c *proxiedConn) extendPrefetchFromTry(force bool) int {
	if c.drain == nil {
		return 0
	}
	if !force && !c.prefetchGate.shouldProbe() {
		return 0
	}
	drained := c.drainTryReceiveBatchIntoPrefetch()
	if shouldObserveDrainProbe(force, drained) {
		c.prefetchGate.observeDrain(drained)
	}
	return drained
}

func (c *proxiedConn) enqueuePrefetchedRaw(data []byte) bool {
	c.prefetchMu.Lock()
	defer c.prefetchMu.Unlock()
	if c.prefetchCount >= proxiedConnPrefetchMax {
		select {
		case c.prefetchNotify <- struct{}{}:
		default:
		}
		return false
	}
	tail := (c.prefetchHead + c.prefetchCount) & proxiedConnPrefetchMask
	c.prefetchSlots[tail] = data
	c.prefetchCount++
	c.prefetchCountAtomic.Store(int32(c.prefetchCount))
	c.signalPrefetchReady()
	return true
}

func (c *proxiedConn) takePrefetched() ([]byte, bool, bool) {
	if c.prefetchCountAtomic.Load() == 0 {
		return nil, false, false
	}
	c.prefetchMu.Lock()
	defer c.prefetchMu.Unlock()
	if c.prefetchCount == 0 {
		c.prefetchCountAtomic.Store(0)
		return nil, false, false
	}
	wasFull := c.prefetchCount == proxiedConnPrefetchMax
	idx := c.prefetchHead
	d := c.prefetchSlots[idx]
	c.prefetchSlots[idx] = nil
	c.prefetchHead = (c.prefetchHead + 1) & proxiedConnPrefetchMask
	c.prefetchCount--
	c.prefetchCountAtomic.Store(int32(c.prefetchCount))
	hasMore := c.prefetchCount > 0
	if wasFull {
		select {
		case c.prefetchNotify <- struct{}{}:
		default:
		}
	}
	return d, true, hasMore
}

func (c *proxiedConn) waitPrefetched(ctx context.Context) ([]byte, error) {
	for {
		if raw, ok, _ := c.takePrefetched(); ok {
			return raw, nil
		}
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-c.prefetchNotify:
		}
	}
}

func (c *proxiedConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	c.startDatagramPump()
	expiredPrefetchDrops := 0
start:
	c.deadlineMx.Lock()
	ctx := c.readCtx
	c.deadlineMx.Unlock()
	ctxDone := ctx.Done()
	ctxCancelled := func() (error, bool) {
		if ctxDone == nil {
			return nil, false
		}
		select {
		case <-ctxDone:
			return ctx.Err(), true
		default:
			return nil, false
		}
	}

	var data []byte
	fromPrefetch := false
	hasBufferedPrefetch := false
	if raw, ok, hasMore := c.takePrefetched(); ok {
		data = raw
		fromPrefetch = true
		hasBufferedPrefetch = hasMore
	} else {
		c.extendPrefetchFromTry(true)
		if raw, ok, hasMore := c.takePrefetched(); ok {
			data = raw
			fromPrefetch = true
			hasBufferedPrefetch = hasMore
		} else {
			data, err = c.waitPrefetched(ctx)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					return 0, nil, err
				}
				c.deadlineMx.Lock()
				restart := time.Now().Before(c.deadline)
				c.deadlineMx.Unlock()
				if restart {
					goto start
				}
				return 0, nil, os.ErrDeadlineExceeded
			}
		}
	}
	payload, ok, parseErr := parseProxiedDatagramPayload(data)
	if parseErr != nil {
		goto dropAndContinue
	}
	if !ok {
		goto dropAndContinue
	}
	if len(payload) == 0 {
		return 0, c.remoteAddr, ErrICMPPortUnreachable
	}
	n = copy(b, payload)
	if !fromPrefetch || !hasBufferedPrefetch {
		c.extendPrefetchFromTry(false)
	}
	return n, c.remoteAddr, nil

dropAndContinue:
	c.deadlineMx.Lock()
	deadlineExceeded := !c.deadline.IsZero() && !time.Now().Before(c.deadline)
	c.deadlineMx.Unlock()
	if deadlineExceeded {
		expiredPrefetchDrops++
		if expiredPrefetchDrops >= proxiedConnExpiredPrefetchDropBudget {
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
	cancelErr, cancelled := ctxCancelled()
	if cancelled {
		if cancelErr != nil && !errors.Is(cancelErr, context.Canceled) {
			return 0, nil, cancelErr
		}
	}
	if (!fromPrefetch || !hasBufferedPrefetch) && !cancelled {
		c.extendPrefetchFromTry(false)
	}
	goto start
}

func (c *proxiedConn) startWritePump() {
	if c.writeFlushSender == nil {
		return
	}
	c.writeOnce.Do(func() {
		c.writeCh = make(chan []byte, proxiedConnWriteQueueCap)
		c.writeDone = make(chan struct{})
		go c.pumpH3C2S()
	})
}

func (c *proxiedConn) pumpH3C2S() {
	defer close(c.writeDone)
	for {
		data, ok := <-c.writeCh
		if !ok {
			break
		}
		c.writeMu.Lock()
		if err := c.sendDatagramLocked(data); err != nil {
			c.storeWriteErr(err)
		}
		for len(c.writeCh) > 0 {
			data = <-c.writeCh
			if err := c.sendDatagramLocked(data); err != nil {
				c.storeWriteErr(err)
			}
		}
		c.flushPendingWriteBatchLocked()
		c.writeMu.Unlock()
	}
	c.writeMu.Lock()
	c.flushPendingWriteBatchLocked()
	c.writeMu.Unlock()
}

func (c *proxiedConn) sendDatagramLocked(data []byte) error {
	if c.writeFlushSender == nil {
		return c.str.SendDatagram(data)
	}
	if err := c.writeFlushSender.SendDatagramNoWake(data); err != nil {
		return err
	}
	c.pendingWriteBatch++
	if c.pendingWriteBatch >= proxiedConnWriteHTTPBatchFlush {
		c.pendingWriteBatch = 0
		c.writeFlushSender.FlushProxiedIPDatagramSend()
	}
	return nil
}

func (c *proxiedConn) flushPendingWriteBatchLocked() {
	if c.writeFlushSender == nil || c.pendingWriteBatch == 0 {
		return
	}
	c.pendingWriteBatch = 0
	c.writeFlushSender.FlushProxiedIPDatagramSend()
}

func (c *proxiedConn) enqueueDatagram(data []byte) error {
	if c.writeFlushSender != nil {
		c.writeMu.Lock()
		err := c.sendDatagramLocked(data)
		c.writeMu.Unlock()
		return err
	}
	return c.str.SendDatagram(data)
}

func (c *proxiedConn) flushPendingWriteBatch() {
	if c.writeFlushSender == nil {
		return
	}
	c.writeMu.Lock()
	pending := c.pendingWriteBatch
	c.pendingWriteBatch = 0
	c.writeMu.Unlock()
	if pending > 0 {
		c.writeFlushSender.FlushProxiedIPDatagramSend()
	}
}

func (c *proxiedConn) storeWriteErr(err error) {
	if err != nil {
		c.writeErr.Store(&err)
	}
}

func (c *proxiedConn) takeWriteErr() error {
	if p := c.writeErr.Swap(nil); p != nil {
		return *p
	}
	return nil
}

func (c *proxiedConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.startDatagramPump()
	if err := c.takeWriteErr(); err != nil {
		return 0, err
	}
	n = len(p)
	minCap := len(contextIDZero) + len(p)
	if c.writeFlushSender != nil {
		c.startWritePump()
		bufPtr := proxiedConnWriteBufPool.Get().(*[]byte)
		data := *bufPtr
		if cap(data) < minCap {
			*bufPtr = data[:0]
			proxiedConnWriteBufPool.Put(bufPtr)
			data = make([]byte, minCap)
			copy(data, contextIDZero)
			copy(data[len(contextIDZero):], p)
		} else {
			data = data[:minCap]
			copy(data, contextIDZero)
			copy(data[len(contextIDZero):], p)
		}
		select {
		case c.writeCh <- data:
			return n, nil
		case <-c.pumpCtx.Done():
			return 0, net.ErrClosed
		}
	}
	bufPtr := proxiedConnWriteBufPool.Get().(*[]byte)
	data := *bufPtr
	if cap(data) >= minCap {
		data = data[:minCap]
		copy(data, contextIDZero)
		copy(data[len(contextIDZero):], p)
		err = c.enqueueDatagram(data)
		*bufPtr = data[:0]
		proxiedConnWriteBufPool.Put(bufPtr)
		return n, err
	}
	*bufPtr = data[:0]
	proxiedConnWriteBufPool.Put(bufPtr)
	b := make([]byte, minCap)
	copy(b, contextIDZero)
	copy(b[len(contextIDZero):], p)
	err = c.enqueueDatagram(b)
	return n, err
}

func parseProxiedDatagramPayload(data []byte) (payload []byte, ok bool, err error) {
	if len(data) == 0 {
		return nil, false, io.EOF
	}
	if data[0] == 0 {
		return data[1:], true, nil
	}
	if data[0]&0xc0 == 0 {
		return nil, false, nil
	}
	if data[0]&0x3f != 0 {
		return nil, false, nil
	}
	switch data[0] >> 6 {
	case 1:
		if len(data) < 2 {
			return nil, false, io.EOF
		}
		if data[1] == 0 {
			return data[2:], true, nil
		}
		return nil, false, nil
	case 2:
		if len(data) < 4 {
			return nil, false, io.EOF
		}
		if data[1] == 0 && data[2] == 0 && data[3] == 0 {
			return data[4:], true, nil
		}
		return nil, false, nil
	case 3:
		if len(data) < 8 {
			return nil, false, io.EOF
		}
		if data[1] == 0 && data[2] == 0 && data[3] == 0 && data[4] == 0 && data[5] == 0 && data[6] == 0 && data[7] == 0 {
			return data[8:], true, nil
		}
		return nil, false, nil
	}
	return nil, false, io.EOF
}

func (c *proxiedConn) FlushC2SWrites() {
	c.flushPendingWriteBatch()
	if c.writeCh == nil {
		return
	}
	deadline := time.Now().Add(proxiedConnWriteCloseDrainWait)
	for time.Now().Before(deadline) {
		if len(c.writeCh) == 0 {
			return
		}
		time.Sleep(50 * time.Microsecond)
	}
}

func (c *proxiedConn) Close() error {
	c.closed.Store(true)
	c.pumpCancel()
	c.signalPrefetchReady()
	c.FlushC2SWrites()
	if c.writeCh != nil {
		c.writeCloseOnce.Do(func() {
			close(c.writeCh)
		})
		select {
		case <-c.writeDone:
		case <-time.After(proxiedConnWriteCloseDrainWait):
		}
	}
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	err := c.str.Close()
	<-c.readDone
	c.readCtxCancel()
	c.deadlineMx.Lock()
	if c.readDeadlineTimer != nil {
		c.readDeadlineTimer.Stop()
	}
	c.deadlineMx.Unlock()
	return err
}

func (c *proxiedConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *proxiedConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *proxiedConn) SetDeadline(t time.Time) error {
	_ = c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}

func (c *proxiedConn) SetReadDeadline(t time.Time) error {
	var (
		cancelOutside  context.CancelFunc
		timerNeedDrain bool
		drainTimer     *time.Timer
	)

	c.deadlineMx.Lock()
	oldDeadline := c.deadline
	c.deadline = t
	now := time.Now()
	if t.IsZero() {
		if c.readDeadlineTimer != nil && !c.readDeadlineTimer.Stop() {
			timerNeedDrain = true
			drainTimer = c.readDeadlineTimer
		}
		c.deadlineMx.Unlock()
		if timerNeedDrain && drainTimer != nil {
			<-drainTimer.C
		}
		return nil
	}
	if !t.After(now) {
		cancelOutside = c.readCtxCancel
		c.deadlineMx.Unlock()
		cancelOutside()
		return nil
	}
	deadline := t.Sub(now)
	if c.readDeadlineTimer != nil {
		replaceReadCtx := now.Before(oldDeadline)
		if !replaceReadCtx && c.readCtx.Err() != nil {
			replaceReadCtx = true
		}
		if replaceReadCtx {
			cancelOutside = c.readCtxCancel
			c.readCtx, c.readCtxCancel = context.WithCancel(context.Background())
		}
		c.readDeadlineTimer.Reset(deadline)
	} else {
		c.readDeadlineTimer = time.AfterFunc(deadline, func() {
			c.deadlineMx.Lock()
			shouldCancel := !c.deadline.IsZero() && c.deadline.Before(time.Now())
			cancelFn := c.readCtxCancel
			c.deadlineMx.Unlock()
			if shouldCancel && cancelFn != nil {
				cancelFn()
			}
		})
	}
	c.deadlineMx.Unlock()
	if cancelOutside != nil {
		cancelOutside()
	}
	return nil
}

func (c *proxiedConn) SetWriteDeadline(time.Time) error {
	return nil
}

func skipCapsules(str quicvarint.Reader) error {
	for {
		ct, r, err := http3.ParseCapsule(str)
		if err != nil {
			return err
		}
		max := int64(skipCapsuleNondatagramMaxPayload)
		if ct == capsuleTypeDatagram {
			max = int64(skipCapsuleDatagramMaxPayload)
		}
		n, err := io.Copy(io.Discard, io.LimitReader(r, max+1))
		if err != nil {
			return err
		}
		if n > max {
			return fmt.Errorf("masque connect-udp h3 skip-capsules: type=%d capsule exceeds %d bytes", ct, max)
		}
	}
}

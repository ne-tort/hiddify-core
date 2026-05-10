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

const proxiedConnPrefetchMax = 512
const proxiedConnPrefetchMask = proxiedConnPrefetchMax - 1
const proxiedConnExpiredPrefetchDropBudget = 64

// Bounds for draining ignored capsules on the HTTP/3 CONNECT-UDP request stream (skipCapsules).
// Parity with sing-box transport/masque h2_connect_udp.go: hostile varints must not drive
// unbounded reads through io.Copy(io.Discard, capsuleBody).
const (
	skipCapsuleDatagramMaxPayload                      = 1500 + 128
	skipCapsuleNondatagramMaxPayload                   = 65536
	capsuleTypeDatagram              http3.CapsuleType = 0
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

	closed   atomic.Bool // set when Close is called
	readDone chan struct{}

	// O(1) dequeue: bounded ring of datagrams drained via TryReceiveDatagram between ReadFrom calls.
	prefetchMu    sync.Mutex
	prefetchSlots [][]byte
	prefetchHead  int
	prefetchCount int
	// Lock-free empty-queue check for hot ReadFrom path.
	prefetchCountAtomic atomic.Int32
	prefetchGate        adaptiveTryDrainGate

	deadlineMx        sync.Mutex
	readCtx           context.Context
	readCtxCancel     context.CancelFunc
	deadline          time.Time
	readDeadlineTimer *time.Timer
}

var _ net.PacketConn = &proxiedConn{}

func newProxiedConn(str http3Stream, local, remote net.Addr) *proxiedConn {
	c := &proxiedConn{
		str:           str,
		drain:         nil,
		localAddr:     local,
		remoteAddr:    remote,
		readDone:      make(chan struct{}),
		prefetchSlots: make([][]byte, proxiedConnPrefetchMax),
	}
	if dr, ok := str.(tryDrainHTTPDatagrams); ok {
		c.drain = dr
	}
	c.readCtx, c.readCtxCancel = context.WithCancel(context.Background())
	go func() {
		defer close(c.readDone)
		if err := skipCapsules(quicvarint.NewReader(str)); err != nil && !errors.Is(err, io.EOF) && !c.closed.Load() {
			log.Printf("reading from request stream failed: %v", err)
		}
		str.Close()
	}()
	return c
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
	idx := c.prefetchHead
	d := c.prefetchSlots[idx]
	c.prefetchSlots[idx] = nil
	c.prefetchHead = (c.prefetchHead + 1) & proxiedConnPrefetchMask
	c.prefetchCount--
	c.prefetchCountAtomic.Store(int32(c.prefetchCount))
	return d, true, c.prefetchCount > 0
}

func (c *proxiedConn) extendPrefetchFromTry() {
	if c.drain == nil {
		return
	}
	// Cheap lock-free probe budget check before taking prefetchMu.
	if !c.prefetchGate.shouldProbe() {
		return
	}
	// Batch drain under one prefetchMu (avoids lock/unlock per datagram).
	c.prefetchMu.Lock()
	defer c.prefetchMu.Unlock()
	drained := 0
	for c.prefetchCount < proxiedConnPrefetchMax {
		raw, ok := c.drain.TryReceiveDatagram()
		if !ok {
			break
		}
		tail := (c.prefetchHead + c.prefetchCount) & proxiedConnPrefetchMask
		c.prefetchSlots[tail] = raw
		c.prefetchCount++
		drained++
	}
	c.prefetchCountAtomic.Store(int32(c.prefetchCount))
	c.prefetchGate.observeDrain(drained)
}

func (c *proxiedConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
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
		data, err = c.str.ReceiveDatagram(ctx)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				return 0, nil, err
			}
			// The context is cancelled asynchronously (in a Go routine spawned from time.AfterFunc).
			// We need to check if a new deadline has already been set.
			c.deadlineMx.Lock()
			restart := time.Now().Before(c.deadline)
			c.deadlineMx.Unlock()
			if restart {
				goto start
			}
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
	payload, ok, err := parseProxiedDatagramPayload(data)
	if err != nil {
		// CONNECT-UDP uses unreliable DATAGRAMs: malformed frames must not tear down the flow.
		cancelErr, cancelled := ctxCancelled()
		if cancelled {
			c.deadlineMx.Lock()
			deadlineExceeded := !c.deadline.IsZero() && !time.Now().Before(c.deadline)
			c.deadlineMx.Unlock()
			if deadlineExceeded {
				expiredPrefetchDrops++
				if expiredPrefetchDrops >= proxiedConnExpiredPrefetchDropBudget {
					return 0, nil, os.ErrDeadlineExceeded
				}
			}
			if cancelErr != nil && !errors.Is(cancelErr, context.Canceled) {
				return 0, nil, cancelErr
			}
		}
		if (!fromPrefetch || !hasBufferedPrefetch) && !cancelled {
			c.extendPrefetchFromTry()
		}
		goto start
	}
	if !ok {
		// Drop this datagram. We currently only support proxying of UDP payloads.
		cancelErr, cancelled := ctxCancelled()
		if cancelled {
			c.deadlineMx.Lock()
			deadlineExceeded := !c.deadline.IsZero() && !time.Now().Before(c.deadline)
			c.deadlineMx.Unlock()
			if deadlineExceeded {
				expiredPrefetchDrops++
				if expiredPrefetchDrops >= proxiedConnExpiredPrefetchDropBudget {
					return 0, nil, os.ErrDeadlineExceeded
				}
			}
			if cancelErr != nil && !errors.Is(cancelErr, context.Canceled) {
				return 0, nil, cancelErr
			}
		}
		if (!fromPrefetch || !hasBufferedPrefetch) && !cancelled {
			c.extendPrefetchFromTry()
		}
		goto start
	}
	// If b is too small, additional bytes are discarded.
	// This mirrors the behavior of large UDP datagrams received on a UDP socket (on Linux).
	n = copy(b, payload)
	if !fromPrefetch || !hasBufferedPrefetch {
		c.extendPrefetchFromTry()
	}
	return n, c.remoteAddr, nil
}

// WriteTo sends a UDP datagram to the target.
// The net.Addr parameter is ignored.
func (c *proxiedConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	n = len(p)
	minCap := len(contextIDZero) + len(p)
	bufPtr := proxiedConnWriteBufPool.Get().(*[]byte)
	data := *bufPtr
	if cap(data) >= minCap {
		data = data[:minCap]
		data[0] = 0
		copy(data[len(contextIDZero):], p)
		err = c.str.SendDatagram(data)
		*bufPtr = data[:0]
		proxiedConnWriteBufPool.Put(bufPtr)
		return n, err
	}
	*bufPtr = data[:0]
	proxiedConnWriteBufPool.Put(bufPtr)
	b := make([]byte, minCap)
	b[0] = 0
	copy(b[len(contextIDZero):], p)
	err = c.str.SendDatagram(b)
	return n, err
}

func parseProxiedDatagramPayload(data []byte) (payload []byte, ok bool, err error) {
	if len(data) == 0 {
		return nil, false, io.EOF
	}
	// CONNECT-UDP hot path: context ID 0 is encoded as one byte 0x00.
	if data[0] == 0 {
		return data[1:], true, nil
	}
	// Fast-reject one-byte non-zero context IDs without quicvarint.Parse.
	// QUIC varint prefixes with 00 use a single byte encoding (0..63).
	if data[0]&0xc0 == 0 {
		return nil, false, nil
	}
	// Fast-reject multi-byte non-zero contexts when high-order varint bits are
	// already non-zero. Context ID 0 can only use this prefix if those bits are zero.
	if data[0]&0x3f != 0 {
		return nil, false, nil
	}
	// Fast-path multi-byte varint with zero high-order bits:
	// - accept canonical 2/4/8-byte zero context-id,
	// - fast-reject non-zero values directly for tolerant-drop path.
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
	// Unreachable after the prefix checks above, but keep a safe malformed fallback.
	return nil, false, io.EOF
}

func (c *proxiedConn) Close() error {
	c.closed.Store(true)
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

func (c *proxiedConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *proxiedConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

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
	// Stop the timer.
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
	// If the deadline already expired, cancel immediately.
	if !t.After(now) {
		cancelOutside = c.readCtxCancel
		c.deadlineMx.Unlock()
		cancelOutside()
		return nil
	}
	deadline := t.Sub(now)
	// if we already have a timer, reset it
	if c.readDeadlineTimer != nil {
		// Within the previous window: replace ctx so ReceiveDatagram abandons the old timer window.
		// After the previous instant has passed, the timer may already have fired and canceled readCtx;
		// if we only Reset without a fresh ctx, ReadFrom can spin (canceled ctx + restart GOTO).
		replaceReadCtx := now.Before(oldDeadline)
		if !replaceReadCtx && c.readCtx.Err() != nil {
			replaceReadCtx = true
		}
		if replaceReadCtx {
			cancelOutside = c.readCtxCancel
			c.readCtx, c.readCtxCancel = context.WithCancel(context.Background())
		}
		c.readDeadlineTimer.Reset(deadline)
	} else { // this is the first time the timer is set
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
	// TODO(#22): This is currently blocked on a change in quic-go's API.
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

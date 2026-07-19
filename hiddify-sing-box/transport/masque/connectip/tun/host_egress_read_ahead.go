package tun

import (
	"context"
	"runtime"
	"sync"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

// hostEgressReadAhead decouples blocking host reads from LoopIn (overlap syscall with write+flush).
type hostEgressReadAhead struct {
	inner HostEgressReader
	mu    sync.Mutex
	cond  *sync.Cond
	q     [][]byte
	ready chan struct{}
	buf   []byte
}

const hostEgressReadAheadMax = 256

const hostEgressPktBufCap = 2048

var hostEgressPktPool sync.Pool

func init() {
	hostEgressPktPool.New = func() any {
		b := make([]byte, hostEgressPktBufCap)
		return &b
	}
}

func acquireHostEgressPkt(n int) []byte {
	bp := hostEgressPktPool.Get().(*[]byte)
	buf := *bp
	if cap(buf) < n {
		return make([]byte, n)
	}
	return buf[:n]
}

func releaseHostEgressPkt(p []byte) {
	if len(p) == 0 {
		return
	}
	c := cap(p)
	if c < 128 || c > 4096 {
		return
	}
	b := p[:c]
	hostEgressPktPool.Put(&b)
}

func cloneHostEgressPkt(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	dst := acquireHostEgressPkt(len(src))
	copy(dst, src)
	return dst
}

// WrapHostEgressReadAheadBatch returns single-pkt and batch readers sharing one background pump.
// Prod always-on (P1-2 KEEP): OFF serializes TUN read behind LoopIn write — H2 TCP UP 314→221, H3 UP 1060→1010.
func WrapHostEgressReadAheadBatch(parent context.Context, inner HostEgressReader) (HostEgressReader, HostEgressBatchReader) {
	return wrapHostEgressReadAhead(parent, inner)
}

func wrapHostEgressReadAhead(parent context.Context, inner HostEgressReader) (HostEgressReader, HostEgressBatchReader) {
	if inner == nil || parent == nil {
		return inner, nil
	}
	r := &hostEgressReadAhead{inner: inner, ready: make(chan struct{}, 1), buf: make([]byte, 2048)}
	r.cond = sync.NewCond(&r.mu)
	go r.pump(parent)
	return r.read, r
}

func (r *hostEgressReadAhead) pump(ctx context.Context) {
	nbDrain := cippump.LoopInNonblockingDrainCtx()
	for {
		if ctx.Err() != nil {
			return
		}
		if !r.pullFromHost(ctx) {
			if ctx.Err() != nil {
				return
			}
			runtime.Gosched()
		}
		for r.pullFromHost(nbDrain) {
		}
	}
}

func (r *hostEgressReadAhead) pullFromHost(ctx context.Context) bool {
	pkt := acquireHostEgressPkt(hostEgressPktBufCap)
	buf := pkt
	n, err := r.inner(ctx, buf[:cap(buf)])
	if err != nil {
		releaseHostEgressPkt(buf[:0])
		if ctx.Err() != nil {
			return false
		}
		return false
	}
	if n <= 0 {
		releaseHostEgressPkt(buf[:0])
		return false
	}
	r.enqueueOwned(buf[:n])
	return true
}

func (r *hostEgressReadAhead) enqueue(pkt []byte) {
	r.enqueueOwned(cloneHostEgressPkt(pkt))
}

func (r *hostEgressReadAhead) enqueueOwned(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	r.mu.Lock()
	for len(r.q) >= hostEgressReadAheadMax {
		r.cond.Wait()
	}
	r.q = append(r.q, pkt)
	r.mu.Unlock()
	select {
	case r.ready <- struct{}{}:
	default:
	}
}

func (r *hostEgressReadAhead) read(ctx context.Context, dst []byte) (int, error) {
	for {
		if n, ok := r.tryDequeueOne(dst); ok {
			return n, nil
		}
		select {
		case <-ctx.Done():
			return 0, context.Cause(ctx)
		case <-r.ready:
		}
	}
}

// ReadBatch dequeues up to maxN prefetched pkts (RunTunnelBatch fast path).
func (r *hostEgressReadAhead) ReadBatch(ctx context.Context, bufs [][]byte, maxN int) (int, error) {
	if maxN < 1 || len(bufs) == 0 {
		return 0, nil
	}
	if maxN > len(bufs) {
		maxN = len(bufs)
	}
	for {
		got := r.tryDequeueBatch(bufs, maxN)
		if got > 0 {
			return got, nil
		}
		select {
		case <-ctx.Done():
			return 0, context.Cause(ctx)
		case <-r.ready:
		}
	}
}

func (r *hostEgressReadAhead) tryDequeueOne(dst []byte) (int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.q) == 0 {
		return 0, false
	}
	pkt := r.q[0]
	r.q = r.q[1:]
	r.cond.Signal()
	n := copy(dst, pkt)
	releaseHostEgressPkt(pkt)
	return n, true
}

func (r *hostEgressReadAhead) tryDequeueBatch(bufs [][]byte, maxN int) int {
	got := 0
	r.mu.Lock()
	defer r.mu.Unlock()
	for got < maxN && len(r.q) > 0 {
		pkt := r.q[0]
		r.q = r.q[1:]
		if len(pkt) > len(bufs[got]) {
			r.q = append([][]byte{pkt}, r.q...)
			break
		}
		copy(bufs[got], pkt)
		releaseHostEgressPkt(pkt)
		got++
	}
	if got > 0 {
		r.cond.Signal()
	}
	return got
}

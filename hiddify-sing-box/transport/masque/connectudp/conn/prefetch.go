package conn

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"time"
)

const (
	h3PrefetchMax               = 512
	h3PrefetchMask              = h3PrefetchMax - 1
	h3PrefetchExpiredDropBudget = 64
	h3PrefetchDrainProbeMaxSkip = 64
)

type tryDrainHTTPDatagrams interface {
	TryReceiveDatagram() ([]byte, bool)
}

type adaptiveTryDrainGate struct {
	skipBudget       atomic.Int32
	emptyProbeStreak atomic.Int32
}

func (g *adaptiveTryDrainGate) shouldProbe() bool {
	for {
		budget := g.skipBudget.Load()
		if budget <= 0 {
			return true
		}
		if g.skipBudget.CompareAndSwap(budget, budget-1) {
			return false
		}
	}
}

func (g *adaptiveTryDrainGate) observeDrain(drained int) {
	if drained > 0 {
		g.skipBudget.Store(0)
		g.emptyProbeStreak.Store(0)
		return
	}
	for {
		streak := g.emptyProbeStreak.Load()
		nextStreak := streak
		if nextStreak < 16 {
			nextStreak++
		}
		if g.emptyProbeStreak.CompareAndSwap(streak, nextStreak) {
			nextSkip := int32(1 << (nextStreak - 1))
			if nextSkip > int32(h3PrefetchDrainProbeMaxSkip) {
				nextSkip = int32(h3PrefetchDrainProbeMaxSkip)
			}
			g.skipBudget.Store(nextSkip)
			return
		}
	}
}

func shouldObservePrefetchDrainProbe(force bool, drained int) bool {
	return !force || drained > 0
}

func (c *H3Conn) startDatagramPump() {
	c.pumpOnce.Do(func() {
		go c.pumpH3Datagrams()
	})
}

func (c *H3Conn) pumpH3Datagrams() {
	for {
		if c.closed.Load() {
			return
		}
		if c.drainTryReceiveIntoPrefetch() > 0 {
			continue
		}
		if c.prefetchCountAtomic.Load() >= h3PrefetchMax {
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

func (c *H3Conn) drainTryReceiveIntoPrefetch() int {
	return c.drainTryReceiveBatchIntoPrefetch()
}

func (c *H3Conn) drainTryReceiveBatchIntoPrefetch() int {
	total := 0
	for c.prefetchCountAtomic.Load() < h3PrefetchMax {
		n := c.drainOneTryReceiveBatch()
		if n == 0 {
			break
		}
		total += n
	}
	return total
}

func (c *H3Conn) drainOneTryReceiveBatch() int {
	if c.drain == nil {
		return 0
	}
	space := h3PrefetchMax - int(c.prefetchCountAtomic.Load())
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
	for i := 0; i < n && c.prefetchCount < h3PrefetchMax; i++ {
		tail := (c.prefetchHead + c.prefetchCount) & h3PrefetchMask
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

func (c *H3Conn) signalPrefetchReady() {
	select {
	case c.prefetchNotify <- struct{}{}:
	default:
	}
}

func (c *H3Conn) extendPrefetchFromTry(force bool) int {
	if c.drain == nil {
		return 0
	}
	if !force && !c.prefetchGate.shouldProbe() {
		return 0
	}
	drained := c.drainTryReceiveBatchIntoPrefetch()
	if shouldObservePrefetchDrainProbe(force, drained) {
		c.prefetchGate.observeDrain(drained)
	}
	return drained
}

func (c *H3Conn) enqueuePrefetchedRaw(data []byte) bool {
	c.prefetchMu.Lock()
	defer c.prefetchMu.Unlock()
	if c.prefetchCount >= h3PrefetchMax {
		select {
		case c.prefetchNotify <- struct{}{}:
		default:
		}
		return false
	}
	tail := (c.prefetchHead + c.prefetchCount) & h3PrefetchMask
	c.prefetchSlots[tail] = data
	c.prefetchCount++
	c.prefetchCountAtomic.Store(int32(c.prefetchCount))
	c.signalPrefetchReady()
	return true
}

func (c *H3Conn) takePrefetched() ([]byte, bool, bool) {
	if c.prefetchCountAtomic.Load() == 0 {
		return nil, false, false
	}
	c.prefetchMu.Lock()
	defer c.prefetchMu.Unlock()
	if c.prefetchCount == 0 {
		c.prefetchCountAtomic.Store(0)
		return nil, false, false
	}
	wasFull := c.prefetchCount == h3PrefetchMax
	idx := c.prefetchHead
	d := c.prefetchSlots[idx]
	c.prefetchSlots[idx] = nil
	c.prefetchHead = (c.prefetchHead + 1) & h3PrefetchMask
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

func (c *H3Conn) waitPrefetched(ctx context.Context) ([]byte, error) {
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

package conn

import (
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	// h3ConnTryDrainMax: bounded non-blocking dequeue after each blocking ReceiveDatagram (relay parity).
	h3ConnTryDrainMax   = 32
	h3S2CPrefetchSlots  = 64
	h3S2CPrefetchMask   = h3S2CPrefetchSlots - 1
)

// tryDrainHTTPDatagrams exposes non-blocking datagram dequeue on quic-go HTTP/3 streams.
type tryDrainHTTPDatagrams interface {
	TryReceiveDatagram() ([]byte, bool)
}

type h3S2CPrefetchRing struct {
	mu    sync.Mutex
	slots [h3S2CPrefetchSlots][]byte
	head  int
	tail  int
	count int
}

func newH3S2CPrefetchRing() *h3S2CPrefetchRing {
	return &h3S2CPrefetchRing{}
}

func (r *h3S2CPrefetchRing) take() ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count == 0 {
		return nil, false
	}
	data := r.slots[r.head]
	r.slots[r.head] = nil
	r.head = (r.head + 1) & h3S2CPrefetchMask
	r.count--
	return data, true
}

func (r *h3S2CPrefetchRing) put(data []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count >= h3S2CPrefetchSlots {
		return false
	}
	r.slots[r.tail] = data
	r.tail = (r.tail + 1) & h3S2CPrefetchMask
	r.count++
	return true
}

func (c *H3Conn) drainTryReceiveIntoPrefetch() int {
	if c.drainer == nil || c.prefetch == nil {
		return 0
	}
	drained := 0
	for i := 0; i < h3ConnTryDrainMax; i++ {
		data, ok := c.drainer.TryReceiveDatagram()
		if !ok {
			break
		}
		drained++
		if !c.prefetch.put(data) {
			quic.ReleaseMasqueDatagramReceiveBuffer(data)
		}
	}
	return drained
}

func (c *H3Conn) runS2CPrefetchPump() {
	const idleBackoff = 25 * time.Microsecond
	for {
		select {
		case <-c.pumpCtx.Done():
			return
		default:
		}
		if c.drainTryReceiveIntoPrefetch() > 0 {
			continue
		}
		select {
		case <-c.pumpCtx.Done():
			return
		case <-time.After(idleBackoff):
		}
	}
}

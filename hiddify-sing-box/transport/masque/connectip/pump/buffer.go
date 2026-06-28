package pump

import "sync"

// DefaultTunnelMTU is the IP frame buffer size for RunTunnel (usque NetBuffer parity + headroom).
const DefaultTunnelMTU = 2048

// NetBuffer is a sync.Pool of fixed-capacity byte slices (usque api/tunnel.go parity).
type NetBuffer struct {
	capacity int
	buf      sync.Pool
}

// NewNetBuffer creates a pool of []byte with the given capacity.
func NewNetBuffer(capacity int) *NetBuffer {
	if capacity <= 0 {
		panic("pump: NetBuffer capacity must be > 0")
	}
	return &NetBuffer{
		capacity: capacity,
		buf: sync.Pool{
			New: func() any {
				b := make([]byte, capacity)
				return &b
			},
		},
	}
}

// Get returns a slice from the pool.
func (n *NetBuffer) Get() []byte {
	if n == nil {
		return make([]byte, DefaultTunnelMTU)
	}
	return *(n.buf.Get().(*[]byte))
}

// Put returns a slice to the pool when capacity matches.
func (n *NetBuffer) Put(buf []byte) {
	if n == nil || cap(buf) != n.capacity {
		return
	}
	n.buf.Put(&buf)
}

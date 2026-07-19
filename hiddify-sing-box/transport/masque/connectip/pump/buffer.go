package pump

import (
	"sync"
	"unsafe"
)

// DefaultTunnelMTU is the IP frame payload capacity for RunTunnel (usque NetBuffer parity).
const DefaultTunnelMTU = 2048

// ProxiedIPDatagramHeadroom matches netstack/vendor/http3 RFC9297 InPlace headroom
// (locked by TestP215HeadroomEquality).
const ProxiedIPDatagramHeadroom = 16

// NetBuffer is a sync.Pool of RFC9297 headroom-backed IP payload slices (PERF-1c).
type NetBuffer struct {
	payloadCap int
	totalCap   int
	buf        sync.Pool
}

var defaultNetBuffer = NewNetBuffer(DefaultTunnelMTU)

// DefaultNetBuffer returns the shared RunTunnel / native L3 host-kernel pool (2048 B payload).
func DefaultNetBuffer() *NetBuffer {
	return defaultNetBuffer
}

// NewNetBuffer creates a pool of payload slices with ProxiedIPDatagramHeadroom before data.
func NewNetBuffer(payloadCap int) *NetBuffer {
	if payloadCap <= 0 {
		panic("pump: NetBuffer capacity must be > 0")
	}
	total := payloadCap + ProxiedIPDatagramHeadroom
	backingCap := payloadCap + 2*ProxiedIPDatagramHeadroom
	n := &NetBuffer{
		payloadCap: payloadCap,
		totalCap:   total,
		buf: sync.Pool{
			New: func() any {
				b := make([]byte, backingCap)
				return &b
			},
		},
	}
	registerNetBufferPool(n)
	return n
}

func init() {
	registerNetBufferPool(defaultNetBuffer)
}

// IsOutboundPoolPayload reports whether ip is a headroom-backed outbound payload slice.
func IsOutboundPoolPayload(ip []byte) bool {
	return len(ip) > 0 && cap(ip) >= len(ip)+ProxiedIPDatagramHeadroom
}

// TryReturnOutboundPayload returns a payload slice to a registered NetBuffer pool when recognized.
func TryReturnOutboundPayload(payload []byte) bool {
	base := reclaimPayloadBuf(payload)
	if base == nil {
		return false
	}
	if pool, ok := poolByTotalCap[cap(base)]; ok {
		pool.returnBase(base)
		return true
	}
	return false
}

var poolByTotalCap = map[int]*NetBuffer{}

func registerNetBufferPool(n *NetBuffer) {
	if n == nil {
		return
	}
	poolByTotalCap[n.totalCap+ProxiedIPDatagramHeadroom] = n
}

// Get returns a payload slice with RFC9297 headroom reserved before the data pointer.
func (n *NetBuffer) Get() []byte {
	if n == nil {
		return make([]byte, DefaultTunnelMTU)
	}
	full := *(n.buf.Get().(*[]byte))
	if cap(full) < n.totalCap+ProxiedIPDatagramHeadroom {
		full = make([]byte, n.totalCap+ProxiedIPDatagramHeadroom)
	}
	full = full[:n.totalCap]
	return full[ProxiedIPDatagramHeadroom:n.totalCap]
}

// Put returns a payload slice to the pool.
func (n *NetBuffer) Put(payload []byte) {
	if n == nil {
		return
	}
	base := reclaimPayloadBuf(payload)
	if base == nil || cap(base) != n.totalCap+ProxiedIPDatagramHeadroom {
		return
	}
	n.returnBase(base)
}

func (n *NetBuffer) returnBase(base []byte) {
	n.buf.Put(&base)
}

func reclaimPayloadBuf(ip []byte) []byte {
	if len(ip) == 0 || !IsOutboundPoolPayload(ip) {
		return nil
	}
	ipStart := uintptr(unsafe.Pointer(unsafe.SliceData(ip)))
	basePtr := unsafe.Pointer(ipStart - uintptr(ProxiedIPDatagramHeadroom))
	fullCap := cap(ip) + ProxiedIPDatagramHeadroom
	return unsafe.Slice((*byte)(basePtr), fullCap)[:0]
}

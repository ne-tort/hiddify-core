package connectip

import "unsafe"

// ProxiedIPDatagramHeadroom is reserved before each outbound IP slice in the netstack pool
// so HTTP/3 can prepend RFC9297 (quarter-stream varint + context ID) without a second copy.
// Must match connect-ip-go.ProxiedIPOutboundHeadroom and http3 proxiedIPDatagramHeadroom.
const ProxiedIPDatagramHeadroom = 16

// IsOutboundPoolSlice reports whether ip is a netstack pool slice with RFC9297 headroom.
func IsOutboundPoolSlice(ip []byte) bool {
	return len(ip) > 0 && cap(ip) >= len(ip)+ProxiedIPDatagramHeadroom
}

func borrowOutboundPayload(n int) []byte {
	total := ProxiedIPDatagramHeadroom + n
	bp := netstackOutboundBufPool.Get().(*[]byte)
	b := *bp
	if cap(b) < total {
		b = make([]byte, total)
	} else {
		b = b[:total]
	}
	return b[ProxiedIPDatagramHeadroom : ProxiedIPDatagramHeadroom+n]
}

func reclaimOutboundPoolBuf(ip []byte) []byte {
	if len(ip) == 0 {
		return nil
	}
	ipStart := uintptr(unsafe.Pointer(unsafe.SliceData(ip)))
	basePtr := unsafe.Pointer(ipStart - uintptr(ProxiedIPDatagramHeadroom))
	fullCap := cap(ip) + ProxiedIPDatagramHeadroom
	return unsafe.Slice((*byte)(basePtr), fullCap)[:0]
}

// FrameFromOutboundIP returns a RFC9297 frame slice backed by the netstack pool buffer when
// prefixLen bytes fit in the reserved headroom.
func FrameFromOutboundIP(ip []byte, prefixLen int) (frame []byte, ok bool) {
	if prefixLen <= 0 || prefixLen > ProxiedIPDatagramHeadroom || len(ip) == 0 || !IsOutboundPoolSlice(ip) {
		return nil, false
	}
	ipStart := uintptr(unsafe.Pointer(unsafe.SliceData(ip)))
	basePtr := unsafe.Pointer(ipStart - uintptr(ProxiedIPDatagramHeadroom))
	fullCap := cap(ip) + ProxiedIPDatagramHeadroom
	full := unsafe.Slice((*byte)(basePtr), fullCap)
	prefixStart := ProxiedIPDatagramHeadroom - prefixLen
	end := ProxiedIPDatagramHeadroom + len(ip)
	if end > fullCap {
		return nil, false
	}
	return full[prefixStart:end], true
}

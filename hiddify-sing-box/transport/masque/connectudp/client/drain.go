package client

import (
	"net"
	"time"
)

// FlushPacketConnWrites drains CONNECT-UDP C2S coalesce buffers through wrapper chains (SOCKS unwrap).
func FlushPacketConnWrites(conn net.PacketConn) {
	for conn != nil {
		if f, ok := conn.(interface{ FlushC2SWrites() }); ok {
			f.FlushC2SWrites()
		}
		up, ok := conn.(interface{ Upstream() any })
		if !ok {
			break
		}
		next, ok := up.Upstream().(net.PacketConn)
		if !ok {
			break
		}
		conn = next
	}
}

// DrainPacketConnUpload flushes coalesced upload and awaits HTTP/2 TLS / H3 datagram send drain.
func DrainPacketConnUpload(conn net.PacketConn, timeout time.Duration) error {
	var drainer interface {
		AwaitUploadDrain(time.Duration) error
	}
	for cur := conn; cur != nil; {
		if d, ok := cur.(interface {
			AwaitUploadDrain(time.Duration) error
		}); ok {
			drainer = d
		}
		up, ok := cur.(interface{ Upstream() any })
		if !ok {
			break
		}
		next, ok := up.Upstream().(net.PacketConn)
		if !ok {
			break
		}
		cur = next
	}
	FlushPacketConnWrites(conn)
	if drainer == nil {
		return nil
	}
	deadline := time.Now().Add(timeout)
	for attempt := 0; attempt < 3; attempt++ {
		rem := time.Until(deadline)
		if rem <= 0 {
			break
		}
		if err := drainer.AwaitUploadDrain(rem); err == nil {
			return nil
		}
		FlushPacketConnWrites(conn)
	}
	rem := time.Until(deadline)
	if rem <= 0 {
		return drainer.AwaitUploadDrain(0)
	}
	return drainer.AwaitUploadDrain(rem)
}

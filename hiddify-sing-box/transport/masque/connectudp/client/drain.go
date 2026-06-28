package client

import (
	"net"
	"time"
)

// FlushPacketConnWrites drains async CONNECT-UDP C2S write queues (SOCKS unwrap chain).
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

// DrainPacketConnUpload flushes coalesced upload and awaits HTTP/2 TLS flush (H2 burst/docker parity).
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
	if drainer != nil {
		return drainer.AwaitUploadDrain(timeout)
	}
	return nil
}

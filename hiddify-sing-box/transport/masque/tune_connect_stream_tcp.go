package masque

import "net"

// masqueConnectStreamTCPKernelBuf is SO_RCVBUF/SO_SNDBUF on the TUN↔stack TCP leg during relay.
const masqueConnectStreamTCPKernelBuf = 16 << 20

type connectStreamUpstream interface {
	Upstream() any
}

// masqueGvisorBulkTunable is implemented by sing-tun gLazyConn (gVisor TUN TCP).
type masqueGvisorBulkTunable interface {
	TuneMasqueBulkRelay()
}

func extractTCPConn(c net.Conn) *net.TCPConn {
	for c != nil {
		if tc, ok := c.(*net.TCPConn); ok {
			return tc
		}
		if u, ok := c.(connectStreamUpstream); ok {
			if up := u.Upstream(); up != nil {
				if nc, ok := up.(net.Conn); ok {
					c = nc
					continue
				}
			}
			return nil
		}
		u, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			return nil
		}
		c = u.NetConn()
	}
	return nil
}

// TuneConnectStreamTCPRelay lowers delayed-ACK latency and raises kernel buffers on the inner TCP
// socket when a MASQUE CONNECT-stream tunnel is relayed through route/conn.
func TuneConnectStreamTCPRelay(c net.Conn) {
	tuneConnectStreamGvisorBulk(c)
	tc := extractTCPConn(c)
	if tc == nil {
		return
	}
	_ = tc.SetNoDelay(true)
	_ = tc.SetReadBuffer(masqueConnectStreamTCPKernelBuf)
	_ = tc.SetWriteBuffer(masqueConnectStreamTCPKernelBuf)
	tuneConnectStreamTCPRelayQuickAck(tc)
}

func tuneConnectStreamGvisorBulk(c net.Conn) {
	for c != nil {
		if t, ok := c.(masqueGvisorBulkTunable); ok {
			t.TuneMasqueBulkRelay()
			return
		}
		if u, ok := c.(connectStreamUpstream); ok {
			up := u.Upstream()
			if up == nil {
				return
			}
			nc, ok := up.(net.Conn)
			if !ok {
				return
			}
			c = nc
			continue
		}
		u, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			return
		}
		c = u.NetConn()
	}
}

package relay

import (
	"net"

	"github.com/sagernet/sing-box/transport/masque/netutil"
)

// TuneTCPOutbound applies best-effort kernel SNDBUF + Nagle-off on onward TCP dials.
// Never lock SO_RCVBUF: SOCK_RCVBUF_LOCK can stall Linux advertised RWND on WAN
// (same class as H2 TLS underlay ~8 Mbit @30 ms). Receive uses tcp_rmem auto-tune.
// Unix: best-effort TCP BBR (parity with MASQUE TLS underlay / H3 QUIC BBR).
func TuneTCPOutbound(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetWriteBuffer(TCPKernelBuf)
		netutil.ApplyMasqueTCPCongestionBestEffort(tc)
	}
}

//go:build linux

package forwarder

import (
	"net"

	"golang.org/x/sys/unix"
)

// onwardPeerBytesAcked returns cumulative payload bytes ACKed by the onward peer
// (TCP_INFO tcpi_bytes_acked), or 0 if unavailable.
func onwardPeerBytesAcked(c net.Conn) uint64 {
	tc, ok := c.(*net.TCPConn)
	if !ok || tc == nil {
		return 0
	}
	var acked uint64
	raw, err := tc.SyscallConn()
	if err != nil {
		return 0
	}
	_ = raw.Control(func(fd uintptr) {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err != nil || info == nil {
			return
		}
		acked = info.Bytes_acked
	})
	return acked
}

//go:build unix

package netutil

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// ApplyMasqueTCPCongestionBestEffort sets TCP_CONGESTION=bbr when the kernel supports it.
// No-op on failure (module missing / restricted namespaces).
func ApplyMasqueTCPCongestionBestEffort(c syscall.Conn) {
	if c == nil {
		return
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr")
	})
}

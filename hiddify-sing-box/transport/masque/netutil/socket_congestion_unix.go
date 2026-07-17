//go:build unix

package netutil

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// ApplyMasqueTCPCongestionBestEffort pins the MASQUE H2 TLS underlay CC to bbr (cubic fallback).
//
// Host defaults like hybla (common on Amnezia/satellite-tuned VPS) can collapse nested
// TCP-in-TCP upload under mild loss. Must run on every dial path — including sing-box
// outbound dialers when route.auto_detect_interface bypasses MasqueTCPDialerControl.
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
		setMasqueTCPCongestionFD(int(fd))
	})
}

func setMasqueTCPCongestionFD(fd int) {
	if err := unix.SetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr"); err != nil {
		_ = unix.SetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION, "cubic")
	}
}

//go:build unix

package netutil

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// MasqueTCPDialerControl is for net.Dialer.Control before connect.
// Sets SO_SNDBUF + TCP_NODELAY=0 only — never SO_RCVBUF (see TuneMasqueTCPSocketBuffers).
func MasqueTCPDialerControl(network, address string, c syscall.RawConn) error {
	_ = network
	_ = address
	var opErr error
	if err := c.Control(func(fd uintptr) {
		opErr = setMasqueTCPSocketOptsFD(int(fd))
	}); err != nil {
		return err
	}
	return opErr
}

func setMasqueTCPSocketOptsFD(fd int) error {
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, MasqueSocketBufferBytes)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 0)
	setMasqueTCPCongestionFD(fd)
	return nil
}

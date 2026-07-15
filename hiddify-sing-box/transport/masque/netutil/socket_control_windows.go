//go:build windows

package netutil

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// MasqueTCPDialerControl is for net.Dialer.Control before connect (SNDBUF + Nagle-on).
func MasqueTCPDialerControl(network, address string, c syscall.RawConn) error {
	_ = network
	_ = address
	var opErr error
	if err := c.Control(func(fd uintptr) {
		opErr = setMasqueTCPSocketOptsFD(windows.Handle(fd))
	}); err != nil {
		return err
	}
	return opErr
}

func setMasqueTCPSocketOptsFD(fd windows.Handle) error {
	_ = windows.SetsockoptInt(fd, windows.SOL_SOCKET, windows.SO_SNDBUF, MasqueSocketBufferBytes)
	_ = windows.SetsockoptInt(fd, windows.IPPROTO_TCP, windows.TCP_NODELAY, 0)
	return nil
}

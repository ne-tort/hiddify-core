package netutil

import (
	"errors"
	"net"
	"syscall"
)

// IsTransientSyscall reports EAGAIN/EWOULDBLOCK/ENOBUFS-class pressure (MASQUE relay + H3 client parity).
func IsTransientSyscall(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EWOULDBLOCK) ||
		errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.EINTR) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET)
}

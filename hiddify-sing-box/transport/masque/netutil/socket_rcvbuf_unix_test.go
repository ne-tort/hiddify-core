//go:build unix

package netutil

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func getSORcvbuf(c syscall.RawConn) (int, error) {
	return getSOInt(c, unix.SO_RCVBUF)
}

func getSOSndbuf(c syscall.RawConn) (int, error) {
	return getSOInt(c, unix.SO_SNDBUF)
}

func getSOInt(c syscall.RawConn, opt int) (int, error) {
	var (
		v     int
		opErr error
	)
	err := c.Control(func(fd uintptr) {
		v, opErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, opt)
	})
	if err != nil {
		return 0, err
	}
	if opErr != nil {
		return 0, opErr
	}
	return v, nil
}

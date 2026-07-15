//go:build windows

package netutil

import (
	"syscall"

	"golang.org/x/sys/windows"
)

func getSORcvbuf(c syscall.RawConn) (int, error) {
	return getSOInt(c, windows.SO_RCVBUF)
}

func getSOSndbuf(c syscall.RawConn) (int, error) {
	return getSOInt(c, windows.SO_SNDBUF)
}

func getSOInt(c syscall.RawConn, opt int) (int, error) {
	var (
		v     int
		opErr error
	)
	err := c.Control(func(fd uintptr) {
		v, opErr = windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, opt)
	})
	if err != nil {
		return 0, err
	}
	if opErr != nil {
		return 0, opErr
	}
	return v, nil
}

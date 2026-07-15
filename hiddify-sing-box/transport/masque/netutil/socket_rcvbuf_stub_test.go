//go:build !unix && !windows

package netutil

import (
	"errors"
	"syscall"
)

func getSORcvbuf(syscall.RawConn) (int, error) {
	return 0, errors.New("SO_RCVBUF probe not wired")
}

func getSOSndbuf(syscall.RawConn) (int, error) {
	return 0, errors.New("SO_SNDBUF probe not wired")
}

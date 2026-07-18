//go:build linux

package listener

import (
	"net"

	"golang.org/x/sys/unix"
)

func tuneUDPSocketBuffers(uc *net.UDPConn) {
	_ = uc.SetReadBuffer(UDPAssociateSocketBuf)
	_ = uc.SetWriteBuffer(UDPAssociateSocketBuf)
	// When rmem_max is tiny (Docker Desktop), SO_RCVBUF is capped; FORCE bypasses the cap
	// with CAP_NET_ADMIN (bench client is privileged:true).
	if actual := udpSockRcvBuf(uc); actual < UDPAssociateSocketBuf {
		_ = udpSockSetForce(uc, unix.SO_RCVBUFFORCE, UDPAssociateSocketBuf)
	}
	if actual := udpSockSndBuf(uc); actual < UDPAssociateSocketBuf {
		_ = udpSockSetForce(uc, unix.SO_SNDBUFFORCE, UDPAssociateSocketBuf)
	}
}

func udpSockRcvBuf(uc *net.UDPConn) int {
	n, err := udpSockGet(uc, unix.SO_RCVBUF)
	if err != nil {
		return 0
	}
	// Linux getsockopt(SO_RCVBUF) returns 2× the set value.
	return n / 2
}

func udpSockSndBuf(uc *net.UDPConn) int {
	n, err := udpSockGet(uc, unix.SO_SNDBUF)
	if err != nil {
		return 0
	}
	return n / 2
}

func udpSockGet(uc *net.UDPConn, opt int) (int, error) {
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		val int
		opErr error
	)
	err = raw.Control(func(fd uintptr) {
		val, opErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, opt)
	})
	if err != nil {
		return 0, err
	}
	return val, opErr
}

func udpSockSetForce(uc *net.UDPConn, opt int, bytes int) error {
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	err = raw.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, opt, bytes)
	})
	if err != nil {
		return err
	}
	if opErr != nil {
		return opErr
	}
	return nil
}

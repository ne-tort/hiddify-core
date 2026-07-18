//go:build !linux

package listener

import "net"

func tuneUDPSocketBuffers(uc *net.UDPConn) {
	_ = uc.SetReadBuffer(UDPAssociateSocketBuf)
	_ = uc.SetWriteBuffer(UDPAssociateSocketBuf)
}

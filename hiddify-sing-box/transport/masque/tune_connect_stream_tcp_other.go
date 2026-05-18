//go:build !linux

package masque

import (
	"io"
	"net"
)

func WrapTCPQuickAckReader(c net.Conn) net.Conn {
	return c
}

func WrapTCPQuickAckWriter(c net.Conn, w io.Writer) io.Writer {
	return w
}

func tuneConnectStreamTCPRelayQuickAck(*net.TCPConn) {}

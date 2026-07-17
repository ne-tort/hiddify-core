//go:build !unix

package netutil

import "net"

func readTCPInfo(c net.Conn) TCPInfoSnapshot {
	_ = c
	return TCPInfoSnapshot{}
}

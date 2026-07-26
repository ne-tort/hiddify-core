//go:build !linux

package forwarder

import "net"

func onwardPeerBytesAcked(c net.Conn) uint64 {
	_ = c
	return 0
}

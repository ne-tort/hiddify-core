package h2

import (
	"net"

	cudpasymconn "github.com/sagernet/sing-box/transport/masque/connectudp/asymconn"
)

// AsymmetricPacketConn splits asymmetric CONNECT-UDP legs (H2 prod dial). Implementation: connectudp/asymconn.
type AsymmetricPacketConn = cudpasymconn.PacketConn

// NewAsymmetricPacketConn wires download ReadFrom with upload WriteTo.
func NewAsymmetricPacketConn(download, upload net.PacketConn, localAddr, remoteAddr net.Addr, onClose func()) *AsymmetricPacketConn {
	return cudpasymconn.NewPacketConn(download, upload, localAddr, remoteAddr, onClose)
}

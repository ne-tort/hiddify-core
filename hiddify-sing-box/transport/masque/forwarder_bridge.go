package masque

import (
	"context"
	"net/netip"

	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
)

type ConnectIPTCPForwarderOptions = fwd.ConnectIPTCPForwarderOptions

// connectIPPacketPlaneConn is the CONNECT-IP session packet I/O surface used by the S2 forwarder.
type connectIPPacketPlaneConn interface {
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) ([]byte, error)
	Close() error
	CurrentPeerPrefixes() []netip.Prefix
}

// RunConnectIPTCPPacketPlaneForwarder terminates IPv4 TCP and UDP inside CONNECT-IP into host
// TCP/UDP dials (S2). See transport/masque/forwarder.
func RunConnectIPTCPPacketPlaneForwarder(ctx context.Context, conn connectIPPacketPlaneConn, o ConnectIPTCPForwarderOptions) error {
	return fwd.RunConnectIPTCPPacketPlaneForwarder(ctx, conn, o)
}

// RewriteConnectIPOutgoingPeerDst rewrites IPv4/IPv6 destination to the assigned peer address.
func RewriteConnectIPOutgoingPeerDst(packet []byte, peerPrefixes []netip.Prefix) []byte {
	return fwd.RewriteOutgoingPeerDst(packet, peerPrefixes)
}

func connectIPForwarderDialAddr(dstIP netip.Addr, port uint16) string {
	return fwd.DialAddr(dstIP, port)
}

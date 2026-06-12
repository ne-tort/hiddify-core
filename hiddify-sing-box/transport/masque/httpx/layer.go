package httpx

import (
	"context"
	"net"

	M "github.com/sagernet/sing/common/metadata"
)

// IPPacketSession is the CONNECT-IP packet plane (RFC 9484).
type IPPacketSession interface {
	ReadPacket(buffer []byte) (int, error)
	WritePacket(buffer []byte) (icmp []byte, err error)
	Close() error
}

// HTTPLayer is the H2/H3 overlay for CONNECT-stream, CONNECT-IP, and CONNECT-UDP.
type HTTPLayer interface {
	LayerName() string // "h2" | "h3"
	DialConnectStream(ctx context.Context, dest M.Socksaddr) (net.Conn, error)
	OpenIPSession(ctx context.Context) (IPPacketSession, error)
	ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error)
}

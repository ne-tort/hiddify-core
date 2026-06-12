package connectip

import (
	"context"
	"net"
	"net/netip"

	M "github.com/sagernet/sing/common/metadata"
)

// PacketSession is the CONNECT-IP unreliable packet plane (ReadPacket / WritePacket).
type PacketSession interface {
	ReadPacket(buffer []byte) (int, error)
	WritePacket(buffer []byte) (icmp []byte, err error)
	Close() error
}

// PacketSessionWithContext is an optional context-aware packet reader.
type PacketSessionWithContext interface {
	ReadPacketWithContext(ctx context.Context, buffer []byte) (int, error)
}

// PrefixSource exposes ADDRESS_ASSIGN snapshots from connect-ip-go.
type PrefixSource interface {
	CurrentAssignedPrefixes() []netip.Prefix
	LocalPrefixes(ctx context.Context) ([]netip.Prefix, error)
}

// SessionBootstrap carries CONNECT-IP session metadata for netstack factory bootstrap.
type SessionBootstrap struct {
	PrefixSource       PrefixSource
	ProfileLocalIPv4   string
	ProfileLocalIPv6   string
	DatagramCeiling    int
	OverlayH2          bool
	TCPDatagramSlack   int
	DatagramCeilingMax int
}

// TCPNetstack dials TCP through a userspace stack backed by CONNECT-IP.
type TCPNetstack interface {
	DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	Close() error
}

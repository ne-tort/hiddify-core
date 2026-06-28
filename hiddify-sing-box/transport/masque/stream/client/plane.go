package client

import (
	"context"
	"net"

	M "github.com/sagernet/sing/common/metadata"
)

// Plane is the CONNECT-stream client dataplane entry (PATH-ISOLATION § WP-STR).
type Plane struct {
	Host HopChainHost
}

// DialTCPStream dials a TCP destination via MASQUE CONNECT-stream.
func (p Plane) DialTCPStream(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	return Dial(ctx, p.Host, destination)
}

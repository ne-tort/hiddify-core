package client

import (
	"context"
	"net"

	M "github.com/sagernet/sing/common/metadata"
)

// Plane wraps a SessionUDP host for CONNECT-UDP overlay operations.
type Plane struct {
	host SessionUDP
}

// NewPlane returns a CONNECT-UDP client plane backed by host.
func NewPlane(host SessionUDP) *Plane {
	return &Plane{host: host}
}

// ListenPacket opens CONNECT-UDP over the current overlay.
func (p *Plane) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return ListenPacket(p.host, ctx, destination)
}

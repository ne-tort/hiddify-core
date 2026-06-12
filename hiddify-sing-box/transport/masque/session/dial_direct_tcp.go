package session

import (
	"context"
	"net"
	"strconv"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
)

// DialDirectTCP dials destination with the system TCP stack (masque-or-direct fallback path).
func DialDirectTCP(ctx context.Context, dialer *net.Dialer, network string, destination M.Socksaddr) (net.Conn, error) {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	default:
	}
	targetHost, err := strm.ResolveDestinationHost(destination)
	if err != nil {
		return nil, err
	}
	port := strconv.Itoa(int(destination.Port))
	addr := net.JoinHostPort(targetHost, port)
	return dialer.DialContext(ctx, network, addr)
}

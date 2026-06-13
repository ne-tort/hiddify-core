package server

import (
	"context"
	"errors"
	"github.com/sagernet/sing-box/transport/masque/session"
	"net"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// EndpointIsReady reports whether the server adapter may accept dial/listen calls.
func EndpointIsReady(startupErr error, ready bool) bool {
	if startupErr != nil {
		return false
	}
	return ready
}

// DialEndpointTCP dials onward TCP for the server endpoint adapter.
func DialEndpointTCP(ctx context.Context, dialer net.Dialer, startupErr error, network string, destination M.Socksaddr) (net.Conn, error) {
	if startupErr != nil {
		return nil, E.Cause(startupErr, "masque server startup failed")
	}
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, E.New("unsupported network for server endpoint: ", network)
	}
	if destination.IsFqdn() {
		return dialer.DialContext(ctx, network, net.JoinHostPort(destination.Fqdn, strconv.Itoa(int(destination.Port))))
	}
	if destination.Addr.IsValid() {
		return dialer.DialContext(ctx, network, net.JoinHostPort(destination.Addr.String(), strconv.Itoa(int(destination.Port))))
	}
	return nil, errors.Join(session.ErrCapability, E.New("invalid destination"))
}

// ListenEndpointPacket opens an ephemeral UDP socket for the server endpoint adapter.
func ListenEndpointPacket(startupErr error) (net.PacketConn, error) {
	if startupErr != nil {
		return nil, E.Cause(startupErr, "masque server startup failed")
	}
	return net.ListenPacket("udp", "")
}

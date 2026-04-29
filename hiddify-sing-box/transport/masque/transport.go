package masque

import (
	"context"
	"net"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

type ClientSession interface {
	DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
	ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
	Close() error
}

type ClientFactory interface {
	NewSession(ctx context.Context, options ClientOptions) (ClientSession, error)
}

type CapabilitySet struct {
	ConnectUDP bool
	ConnectIP  bool
}

type ClientOptions struct {
	Tag           string
	Server        string
	ServerPort    uint16
	TransportMode string
	Hops          []HopOptions
}

type HopOptions struct {
	Tag    string
	Via    string
	Server string
	Port   uint16
}

type DirectClientFactory struct{}

func (f DirectClientFactory) NewSession(ctx context.Context, options ClientOptions) (ClientSession, error) {
	return &directSession{
		dialer:       net.Dialer{},
		capabilities: CapabilitySet{ConnectUDP: true, ConnectIP: true},
	}, nil
}

type directSession struct {
	dialer       net.Dialer
	capabilities CapabilitySet
}

func (s *directSession) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch strings.ToLower(network) {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, E.New("unsupported network in masque session: ", network)
	}
	if destination.IsFqdn() {
		return s.dialer.DialContext(ctx, network, net.JoinHostPort(destination.Fqdn, strconv.Itoa(int(destination.Port))))
	}
	if destination.Addr.IsValid() {
		return s.dialer.DialContext(ctx, network, net.JoinHostPort(destination.Addr.String(), strconv.Itoa(int(destination.Port))))
	}
	return nil, E.New("invalid destination")
}

func (s *directSession) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !s.capabilities.ConnectUDP {
		return nil, E.New("masque backend does not support CONNECT-UDP")
	}
	return net.ListenPacket("udp", "")
}

func (s *directSession) Close() error { return nil }


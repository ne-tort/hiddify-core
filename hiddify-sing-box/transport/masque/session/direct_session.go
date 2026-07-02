package session

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// DirectSession is the plain-TCP backend (CONNECT-stream / CONNECT-UDP without MASQUE overlay).
type DirectSession struct {
	dialer       net.Dialer
	connectIP    bool
	capabilities CapabilitySet
}

// NewDirectSession constructs a direct backend session from client options.
func NewDirectSession(_ context.Context, options ClientOptions) (ClientSession, error) {
	connectIP := DataplaneUsesConnectIP(options.DataplaneMode)
	return &DirectSession{
		dialer:    net.Dialer{},
		connectIP: connectIP,
		capabilities: CapabilitySet{
			ConnectUDP: !connectIP,
			ConnectIP:  connectIP,
			ConnectTCP: !connectIP,
		},
	}, nil
}

func (s *DirectSession) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch strings.ToLower(network) {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, UnsupportedNetworkError(network)
	}
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	default:
	}
	if s.connectIP {
		return nil, errors.Join(DirectBackendErrs.TCPOverConnectIP, errors.New("connect_ip is TUN packet-plane only"))
	}
	host, err := strm.ResolveDestinationHost(destination)
	if err != nil {
		return nil, err
	}
	return s.dialer.DialContext(ctx, network, net.JoinHostPort(host, strconv.Itoa(int(destination.Port))))
}

func (s *DirectSession) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	default:
	}
	if !s.capabilities.ConnectUDP {
		return nil, E.New("masque backend does not support CONNECT-UDP")
	}
	return net.ListenPacket("udp", "")
}

func (s *DirectSession) OpenIPSession(ctx context.Context) (IPPacketSession, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	default:
	}
	if !s.capabilities.ConnectIP {
		return nil, errors.Join(DirectBackendErrs.Capability, errors.New("masque backend does not support CONNECT-IP"))
	}
	return nil, errors.Join(DirectBackendErrs.Capability, errors.New("CONNECT-IP is not available in direct backend"))
}

func (s *DirectSession) Capabilities() CapabilitySet {
	return s.capabilities
}

func (s *DirectSession) Close() error { return nil }

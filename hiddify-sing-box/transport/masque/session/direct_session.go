package session

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// DirectSession is the plain-TCP backend (CONNECT-stream / CONNECT-UDP without MASQUE overlay).
type DirectSession struct {
	dialer       net.Dialer
	tcpTransport string
	capabilities CapabilitySet
}

// NewDirectSession constructs a direct backend session from client options.
func NewDirectSession(_ context.Context, options ClientOptions) (ClientSession, error) {
	tcpTransport := NormalizeTCPTransport(options.TCPTransport)
	return &DirectSession{
		dialer:       net.Dialer{},
		tcpTransport: tcpTransport,
		capabilities: CapabilitySet{
			ConnectUDP: true,
			ConnectIP:  false,
			ConnectTCP: tcpTransport == option.MasqueTCPTransportConnectStream,
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
	switch s.tcpTransport {
	case option.MasqueTCPTransportConnectIP:
		return nil, errors.Join(DirectBackendErrs.TCPOverConnectIP, errors.New("connect_ip is TUN packet-plane only"))
	case option.MasqueTCPTransportConnectStream:
	default:
		return nil, DirectBackendErrs.TCPPathNotImplemented
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

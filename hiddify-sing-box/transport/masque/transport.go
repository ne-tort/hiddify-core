package masque

import (
	"net"

	"github.com/quic-go/quic-go"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
	"github.com/sagernet/sing-box/transport/masque/session"
)

const defaultUDPInitialPacketSize = h3t.DefaultUDPInitialPacketSize

func masqueQUICConfigForDial(opts ClientOptions) *quic.Config {
	return session.QUICConfigForDial(opts)
}

func masqueTCPConnectStreamQUICConfig(opts ClientOptions) *quic.Config {
	return session.TCPConnectStreamQUICConfig(opts)
}

func masqueTCPConnectStreamHTTP3EnableDatagrams(opts ClientOptions) bool {
	return session.TCPConnectStreamHTTP3EnableDatagrams(opts)
}

// MasqueTCPConnectStreamQUICConfig exposes bulk TCP CONNECT-stream QUIC tuning for isolated
// clients (masque-thin-client, h3 authority) without importing package h3.
func MasqueTCPConnectStreamQUICConfig(opts ClientOptions) *quic.Config {
	return session.TCPConnectStreamQUICConfig(opts)
}

// MasqueHTTPServerQUICConfig returns QUIC settings for the MASQUE HTTP/3 server listener.
func MasqueHTTPServerQUICConfig() *quic.Config {
	return session.HTTPServerQUICConfig()
}

// MasqueAuthorityHTTPServerQUICConfig is QUIC tuning for authority-only HTTP/3 listeners (no datagram plane).
func MasqueAuthorityHTTPServerQUICConfig() *quic.Config {
	return session.AuthorityHTTPServerQUICConfig()
}

// ErrQUICPacketConnContract is re-exported from session for protocol/masque and tests.
var ErrQUICPacketConnContract = session.ErrQUICPacketConnContract

func unsupportedNetworkError(network string) error {
	return session.UnsupportedNetworkError(network)
}

func ValidateQUICTransportPacketConn(c net.PacketConn, path string) error {
	return session.ValidateQUICTransportPacketConn(c, path)
}

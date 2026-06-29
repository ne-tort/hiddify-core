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

// MasqueTCPConnectStreamQUICConfig exposes bulk TCP CONNECT-stream QUIC tuning for external
// dial/bootstrap callers without importing package h3.
func MasqueTCPConnectStreamQUICConfig(opts ClientOptions) *quic.Config {
	return session.TCPConnectStreamQUICConfig(opts)
}

// MasqueHTTPServerQUICConfig returns QUIC settings for the MASQUE HTTP/3 server listener.
func MasqueHTTPServerQUICConfig() *quic.Config {
	return session.HTTPServerQUICConfig()
}

// MasqueH3HTTPServerQUICConfig is QUIC tuning for standalone HTTP/3 listeners (no datagram plane).
func MasqueH3HTTPServerQUICConfig() *quic.Config {
	return session.H3HTTPServerQUICConfig()
}

func unsupportedNetworkError(network string) error {
	return session.UnsupportedNetworkError(network)
}

func ValidateQUICTransportPacketConn(c net.PacketConn, path string) error {
	return session.ValidateQUICTransportPacketConn(c, path)
}

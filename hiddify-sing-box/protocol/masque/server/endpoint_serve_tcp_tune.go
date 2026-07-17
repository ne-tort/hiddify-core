package server

import (
	"net"

	"github.com/sagernet/sing-box/transport/masque/netutil"
)

// masqueTunedTCPListener applies client-parity TLS-underlay tune before wrap:
// SO_SNDBUF 4 MiB + Nagle-on + TCP_CONGESTION bbr/cubic. Never SO_RCVBUF.
// Tracking is done post-handshake (masqueTrackedTLSListener) so TCP_INFO sees live traffic.
type masqueTunedTCPListener struct {
	net.Listener
}

func (l *masqueTunedTCPListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		netutil.TuneMasqueTCPSocketBuffers(tc)
	} else if bc, ok := c.(interface {
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	}); ok {
		netutil.TuneMasqueTCPSocketBuffers(bc)
	}
	return c, nil
}

// masqueTrackedTLSListener registers underlay TCP_INFO after TLS Accept (unwraps tls.Conn).
type masqueTrackedTLSListener struct {
	net.Listener
	role string
}

func (l *masqueTrackedTLSListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	role := l.role
	if role == "" {
		role = "h2-server"
	}
	netutil.TrackTCPUnderlay(role, c)
	return c, nil
}

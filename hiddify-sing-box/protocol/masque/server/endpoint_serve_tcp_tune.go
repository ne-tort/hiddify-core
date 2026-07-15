package server

import (
	"net"

	"github.com/sagernet/sing-box/transport/masque/netutil"
)

// masqueTunedTCPListener applies client-parity TLS-underlay tune before wrap:
// SO_SNDBUF 4 MiB + Nagle-on + best-effort TCP BBR (Unix). Never SO_RCVBUF.
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
		netutil.ApplyMasqueTCPCongestionBestEffort(tc)
	} else if bc, ok := c.(interface {
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	}); ok {
		netutil.TuneMasqueTCPSocketBuffers(bc)
	}
	return c, nil
}

package masque

import (
	"net"

	"github.com/sagernet/sing-box/transport/masque/h3"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

func unwrapH3TunnelConn(conn net.Conn) (*h3.TunnelConn, bool) {
	for conn != nil {
		if tc, ok := conn.(*h3.TunnelConn); ok {
			return tc, true
		}
		switch u := conn.(type) {
		case *strm.TunnelConn:
			conn = u.Inner
		case interface{ TunnelInner() net.Conn }:
			conn = u.TunnelInner()
		default:
			return nil, false
		}
	}
	return nil, false
}

package connectudp

import "net"

// H2ConnectProto is the RFC 8441 :protocol token for CONNECT-UDP over HTTP/2.
const H2ConnectProto = "connect-udp"

// UDPAddr is a CONNECT-UDP net.Addr for LocalAddr/RemoteAddr on H2 capsule tunnels.
type UDPAddr struct{ S string }

// NewUDPAddr builds a CONNECT-UDP net.Addr for LocalAddr/RemoteAddr.
func NewUDPAddr(s string) net.Addr { return UDPAddr{S: s} }

func (m UDPAddr) Network() string { return H2ConnectProto }
func (m UDPAddr) String() string  { return m.S }

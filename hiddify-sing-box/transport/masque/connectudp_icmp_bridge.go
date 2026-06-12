package masque

import (
	"net"

	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	cudp "github.com/sagernet/sing-box/transport/masque/connectudp"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// ErrUDPPortUnreachable signals CONNECT-UDP relay delivered ICMP destination-unreachable.
var ErrUDPPortUnreachable = cudp.ErrPortUnreachable

// UDPPortUnreachableError is returned from CONNECT-UDP ReadFrom/ReadPacket when the relay
// delivered ICMP destination-unreachable (empty RFC 9297 DATAGRAM).
type UDPPortUnreachableError = cudp.PortUnreachableError

// UDPPortUnreachableRemote extracts the unreachable peer from a UDP read error (CONNECT-UDP or CONNECT-IP bridge).
func UDPPortUnreachableRemote(err error, fallback M.Socksaddr) M.Socksaddr {
	if remote := cudp.PortUnreachableRemote(err, fallback); remote.IsValid() {
		return remote
	}
	return cip.ICMPPortUnreachableRemote(err, fallback)
}

// IsUDPPortUnreachable reports whether err is ICMP port-unreachable on a UDP dataplane read.
func IsUDPPortUnreachable(err error) bool {
	return cudp.IsPortUnreachable(err) || cip.IsICMPPortUnreachable(err)
}

// WrapUDPPortUnreachable preserves Remote when re-wrapping for observability.
func WrapUDPPortUnreachable(remote net.Addr, err error) error {
	if !cudp.IsPortUnreachable(err) {
		return err
	}
	if remote == nil {
		return err
	}
	return E.Extend(ErrUDPPortUnreachable, &UDPPortUnreachableError{Remote: M.SocksaddrFromNet(remote).Unwrap()})
}

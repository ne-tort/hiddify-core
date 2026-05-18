package masque

import (
	"errors"
	"net"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// UDPPortUnreachableError is returned from CONNECT-UDP ReadFrom/ReadPacket when the relay
// delivered ICMP destination-unreachable (empty RFC 9297 DATAGRAM). route.copyPacketDownload
// uses Remote to inject ICMP into the TUN stack for bench dig / apps on gVisor/mixed.
type UDPPortUnreachableError struct {
	Remote M.Socksaddr
}

func (e *UDPPortUnreachableError) Error() string {
	return ErrUDPPortUnreachable.Error()
}

func (e *UDPPortUnreachableError) Is(target error) bool {
	return target == ErrUDPPortUnreachable
}

func newUDPPortUnreachableError(remote net.Addr) error {
	if remote == nil {
		return ErrUDPPortUnreachable
	}
	return &UDPPortUnreachableError{Remote: M.SocksaddrFromNet(remote).Unwrap()}
}

// UDPPortUnreachableRemote extracts the unreachable peer from a CONNECT-UDP read error.
func UDPPortUnreachableRemote(err error, fallback M.Socksaddr) M.Socksaddr {
	var pe *UDPPortUnreachableError
	if errors.As(err, &pe) && pe.Remote.IsValid() {
		return pe.Remote
	}
	if fallback.IsValid() {
		return fallback
	}
	return M.Socksaddr{}
}

// IsUDPPortUnreachable reports whether err is masque CONNECT-UDP ICMP port-unreachable.
func IsUDPPortUnreachable(err error) bool {
	return errors.Is(err, ErrUDPPortUnreachable)
}

// WrapUDPPortUnreachable preserves Remote when re-wrapping for observability.
func WrapUDPPortUnreachable(remote net.Addr, err error) error {
	if !IsUDPPortUnreachable(err) {
		return err
	}
	if remote == nil {
		return err
	}
	return E.Extend(ErrUDPPortUnreachable, &UDPPortUnreachableError{Remote: M.SocksaddrFromNet(remote).Unwrap()})
}

package split

import (
	"errors"
	"net"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// ErrPortUnreachable signals CONNECT-UDP relay delivered ICMP destination-unreachable
// (empty RFC 9297 DATAGRAM payload).
var ErrPortUnreachable = E.New("masque connect-udp icmp port unreachable")

// PortUnreachableError is returned from CONNECT-UDP ReadFrom/ReadPacket when the relay
// delivered ICMP destination-unreachable (empty RFC 9297 DATAGRAM).
type PortUnreachableError struct {
	Remote M.Socksaddr
}

func (e *PortUnreachableError) Error() string {
	return ErrPortUnreachable.Error()
}

func (e *PortUnreachableError) Is(target error) bool {
	return target == ErrPortUnreachable
}

// NewPortUnreachableError builds a CONNECT-UDP ICMP port-unreachable read error with peer Remote.
func NewPortUnreachableError(remote net.Addr) error {
	if remote == nil {
		return ErrPortUnreachable
	}
	return &PortUnreachableError{Remote: M.SocksaddrFromNet(remote).Unwrap()}
}

// PortUnreachableRemote extracts the unreachable peer from a CONNECT-UDP read error.
func PortUnreachableRemote(err error, fallback M.Socksaddr) M.Socksaddr {
	var pe *PortUnreachableError
	if errors.As(err, &pe) && pe.Remote.IsValid() {
		return pe.Remote
	}
	if fallback.IsValid() {
		return fallback
	}
	return M.Socksaddr{}
}

// IsPortUnreachable reports whether err is CONNECT-UDP ICMP port-unreachable.
func IsPortUnreachable(err error) bool {
	return errors.Is(err, ErrPortUnreachable)
}

// WrapPortUnreachable preserves Remote when re-wrapping for observability.
func WrapPortUnreachable(remote net.Addr, err error) error {
	if !IsPortUnreachable(err) {
		return err
	}
	if remote == nil {
		return err
	}
	return E.Extend(ErrPortUnreachable, &PortUnreachableError{Remote: M.SocksaddrFromNet(remote).Unwrap()})
}

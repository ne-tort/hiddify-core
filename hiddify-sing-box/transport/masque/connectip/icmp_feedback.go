package connectip

import (
	"errors"
	"net"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// ErrICMPPortUnreachable signals CONNECT-IP UDP bridge ICMP destination-unreachable feedback
// from connect-ip-go WritePacket (full IPv4 ICMP embedding the original datagram).
var ErrICMPPortUnreachable = E.New("masque connect-ip icmp port unreachable")

// ICMPPortUnreachableError carries the unreachable UDP peer for CONNECT-IP bridge reads.
type ICMPPortUnreachableError struct {
	Remote M.Socksaddr
}

func (e *ICMPPortUnreachableError) Error() string {
	return ErrICMPPortUnreachable.Error()
}

func (e *ICMPPortUnreachableError) Is(target error) bool {
	return target == ErrICMPPortUnreachable
}

// NewICMPPortUnreachableError builds a CONNECT-IP ICMP port-unreachable read error with peer Remote.
func NewICMPPortUnreachableError(remote net.Addr) error {
	if remote == nil {
		return ErrICMPPortUnreachable
	}
	return &ICMPPortUnreachableError{Remote: M.SocksaddrFromNet(remote).Unwrap()}
}

// ICMPPortUnreachableRemote extracts the unreachable peer from a CONNECT-IP bridge read error.
func ICMPPortUnreachableRemote(err error, fallback M.Socksaddr) M.Socksaddr {
	var pe *ICMPPortUnreachableError
	if errors.As(err, &pe) && pe.Remote.IsValid() {
		return pe.Remote
	}
	if fallback.IsValid() {
		return fallback
	}
	return M.Socksaddr{}
}

// IsICMPPortUnreachable reports whether err is CONNECT-IP ICMP port-unreachable feedback.
func IsICMPPortUnreachable(err error) bool {
	return errors.Is(err, ErrICMPPortUnreachable)
}

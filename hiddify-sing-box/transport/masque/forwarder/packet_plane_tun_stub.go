//go:build !linux

package forwarder

import (
	"errors"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

// OpenConnectIPServerPacketDevice is Linux-only (host TUN).
func OpenConnectIPServerPacketDevice() (cippump.TunnelDevice, error) {
	return nil, errors.New("connect-ip packet TUN: unsupported platform (linux only)")
}

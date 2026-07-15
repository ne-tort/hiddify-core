//go:build !unix && !windows

package netutil

import "syscall"

// MasqueTCPDialerControl is a no-op on platforms without buffer Control wiring.
func MasqueTCPDialerControl(network, address string, c syscall.RawConn) error {
	_ = network
	_ = address
	_ = c
	return nil
}

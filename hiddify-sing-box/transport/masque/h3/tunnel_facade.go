package h3

import (
	"io"
	"net"
)

// TunnelFacade is the minimal route-facing H3 TCP tunnel contract.
type TunnelFacade interface {
	net.Conn
	io.ReaderFrom
	io.WriterTo
	TunnelPolicySnapshot() TunnelPolicySnapshot
}

// TunnelPolicySnapshot captures the effective H3 tunnel dataplane.
type TunnelPolicySnapshot struct {
	RouteBidiDuplex bool
	UsesH3Stream    bool
}

func (c *TunnelConn) TunnelPolicySnapshot() TunnelPolicySnapshot {
	if c == nil {
		return TunnelPolicySnapshot{}
	}
	return TunnelPolicySnapshot{
		RouteBidiDuplex: false,
		UsesH3Stream:    c.h3 != nil,
	}
}

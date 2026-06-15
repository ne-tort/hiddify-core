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

// TunnelPolicySnapshot captures the effective H3 tunnel mode without exposing mutable internals.
type TunnelPolicySnapshot struct {
	Mode            ConnectStreamMode
	Role            ConnectStreamRole
	RouteBidiDuplex bool
	UsesH3Stream    bool
}

func (c *TunnelConn) TunnelPolicySnapshot() TunnelPolicySnapshot {
	if c == nil {
		return TunnelPolicySnapshot{Mode: CurrentConnectStreamMode()}
	}
	mode := ConnectStreamModeSingleBidi
	if c.h3 == nil {
		mode = ConnectStreamModeSingleBidi
	}
	return TunnelPolicySnapshot{
		Mode:            mode,
		Role:            c.connectStreamRole,
		RouteBidiDuplex: c.routeBidiDuplex,
		UsesH3Stream:    c.h3 != nil,
	}
}

var _ TunnelFacade = (*TunnelConn)(nil)

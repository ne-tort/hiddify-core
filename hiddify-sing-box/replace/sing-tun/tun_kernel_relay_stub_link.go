//go:build with_gvisor && linux

package tun

import (
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

// kernelRelayStubLink is a non-reading link endpoint for native L3 host-kernel relay.
// usque parity: tun fd is read only by CONNECT-IP LoopIn (ReadHostEgress), not fdbased.
type kernelRelayStubLink struct{}

var _ stack.LinkEndpoint = (*kernelRelayStubLink)(nil)

func (kernelRelayStubLink) MTU() uint32 { return 65535 }

func (kernelRelayStubLink) SetMTU(uint32) {}

func (kernelRelayStubLink) Capabilities() stack.LinkEndpointCapabilities { return 0 }

func (kernelRelayStubLink) MaxHeaderLength() uint16 { return 0 }

func (kernelRelayStubLink) LinkAddress() tcpip.LinkAddress { return "" }

func (kernelRelayStubLink) SetLinkAddress(tcpip.LinkAddress) {}

func (kernelRelayStubLink) Attach(stack.NetworkDispatcher) {}

func (kernelRelayStubLink) IsAttached() bool { return false }

func (kernelRelayStubLink) Wait() {}

func (kernelRelayStubLink) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }

func (kernelRelayStubLink) AddHeader(*stack.PacketBuffer) {}

func (kernelRelayStubLink) ParseHeader(*stack.PacketBuffer) bool { return true }

func (kernelRelayStubLink) WritePackets(stack.PacketBufferList) (int, tcpip.Error) {
	return 0, nil
}

func (kernelRelayStubLink) Close() {}

func (kernelRelayStubLink) SetOnCloseAction(func()) {}

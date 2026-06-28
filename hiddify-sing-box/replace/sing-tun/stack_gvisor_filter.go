//go:build with_gvisor

package tun

import (
	"net/netip"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

// overlayStackEgress routes gVisor stack egress to L3OverlaySend when dst is in overlay prefix table.
// Local tun host delivery (SYN-ACK to app) stays on tun WritePacket.
func overlayStackEgress(l3Send func([]byte) error, prefixes []netip.Prefix, broadcast netip.Addr, destination netip.Addr) bool {
	if l3Send == nil || len(prefixes) == 0 {
		return false
	}
	if destination == broadcast || !destination.IsGlobalUnicast() {
		return false
	}
	return prefixListContains(prefixes, destination)
}

var _ stack.LinkEndpoint = (*LinkEndpointFilter)(nil)

type linkEndpointAttachCapture struct {
	stack.LinkEndpoint
	onAttach func(stack.NetworkDispatcher)
}

func (c *linkEndpointAttachCapture) Attach(dispatcher stack.NetworkDispatcher) {
	if c.onAttach != nil {
		c.onAttach(dispatcher)
	}
	c.LinkEndpoint.Attach(dispatcher)
}

type LinkEndpointFilter struct {
	stack.LinkEndpoint
	BroadcastAddress   netip.Addr
	Writer             GVisorTun
	L3OverlayPrefixes  []netip.Prefix
	L3OverlaySend      func([]byte) error
	L3OverlaySendError func(error)
	KernelHostRelay    bool
}

func (w *LinkEndpointFilter) Attach(dispatcher stack.NetworkDispatcher) {
	w.LinkEndpoint.Attach(&networkDispatcherFilter{
		NetworkDispatcher: dispatcher,
		broadcastAddress:  w.BroadcastAddress,
		writer:            w.Writer,
		l3Prefixes:        w.L3OverlayPrefixes,
		l3Send:            w.L3OverlaySend,
		l3SendError:       w.L3OverlaySendError,
		kernelHostRelay:   w.KernelHostRelay,
	})
}

// WritePackets routes gVisor stack egress to L3OverlaySend (CONNECT-IP wire) when overlay is active.
// Without this, ACKs after direct inject never reach the MASQUE plane (tun fd write only).
func (w *LinkEndpointFilter) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if w.L3OverlaySend == nil || len(w.L3OverlayPrefixes) == 0 {
		return w.LinkEndpoint.WritePackets(pkts)
	}
	var (
		written        int
		remainder      stack.PacketBufferList
		remainderCount int
	)
	for _, pkt := range pkts.AsSlice() {
		if w.deliverOverlayEgress(pkt) {
			written++
			continue
		}
		remainder.PushBack(pkt)
		remainderCount++
	}
	if remainderCount == 0 {
		return written, nil
	}
	n, err := w.LinkEndpoint.WritePackets(remainder)
	return written + n, err
}

func (w *LinkEndpointFilter) deliverOverlayEgress(pkt *stack.PacketBuffer) bool {
	if pkt == nil || w.L3OverlaySend == nil {
		return false
	}
	var network header.Network
	switch header.IPVersion(pkt.Data().AsRange().ToSlice()) {
	case header.IPv4Version:
		if headerPackets, loaded := pkt.Data().PullUp(header.IPv4MinimumSize); loaded {
			network = header.IPv4(headerPackets)
		}
	case header.IPv6Version:
		if headerPackets, loaded := pkt.Data().PullUp(header.IPv6MinimumSize); loaded {
			network = header.IPv6(headerPackets)
		}
	}
	if network == nil {
		return false
	}
	destination := AddrFromAddress(network.DestinationAddress())
	if !overlayStackEgress(w.L3OverlaySend, w.L3OverlayPrefixes, w.BroadcastAddress, destination) {
		return false
	}
	packetSlice := append([]byte(nil), pkt.Data().AsRange().ToSlice()...)
	if err := w.L3OverlaySend(packetSlice); err != nil && w.L3OverlaySendError != nil {
		w.L3OverlaySendError(err)
	}
	return true
}

var _ stack.NetworkDispatcher = (*networkDispatcherFilter)(nil)

type networkDispatcherFilter struct {
	stack.NetworkDispatcher
	broadcastAddress netip.Addr
	writer           GVisorTun
	l3Prefixes       []netip.Prefix
	l3Send           func([]byte) error
	l3SendError      func(error)
	kernelHostRelay  bool
}

func (w *networkDispatcherFilter) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	var network header.Network
	if protocol == header.IPv4ProtocolNumber {
		if headerPackets, loaded := pkt.Data().PullUp(header.IPv4MinimumSize); loaded {
			network = header.IPv4(headerPackets)
		}
	} else {
		if headerPackets, loaded := pkt.Data().PullUp(header.IPv6MinimumSize); loaded {
			network = header.IPv6(headerPackets)
		}
	}
	if network == nil {
		w.NetworkDispatcher.DeliverNetworkPacket(protocol, pkt)
		return
	}
	destination := AddrFromAddress(network.DestinationAddress())
	if destination == w.broadcastAddress || !destination.IsGlobalUnicast() {
		w.writer.WritePacket(pkt)
		return
	}
	// Kernel egress (tun read → stack): relay overlay dst to wire without gVisor TCP (usque Device.ReadPacket).
	if w.deliverOverlayIngress(pkt, destination) {
		return
	}
	// Host kernel owns TCP on tun; do not inject tun reads into gVisor stack (RST/orphan SYN-ACK).
	if w.kernelHostRelay {
		return
	}
	w.NetworkDispatcher.DeliverNetworkPacket(protocol, pkt)
}

func (w *networkDispatcherFilter) deliverOverlayIngress(pkt *stack.PacketBuffer, destination netip.Addr) bool {
	if pkt == nil || w.l3Send == nil {
		return false
	}
	if !overlayStackEgress(w.l3Send, w.l3Prefixes, w.broadcastAddress, destination) {
		return false
	}
	packetSlice := append([]byte(nil), pkt.Data().AsRange().ToSlice()...)
	if err := w.l3Send(packetSlice); err != nil && w.l3SendError != nil {
		w.l3SendError(err)
	}
	return true
}

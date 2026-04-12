//go:build with_gvisor

package awg

import (
	"context"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/icmp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/ping"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	awgTun "github.com/amnezia-vpn/amneziawg-go/tun"
)

var _ NatDevice = (*awgStackDevice)(nil)

type awgStackDevice struct {
	ctx              context.Context
	logger           log.ContextLogger
	stack            *stack.Stack
	mtu              uint32
	events           chan awgTun.Event
	outbound         chan *stack.PacketBuffer
	packetOutbound   chan *buf.Buffer
	done             chan struct{}
	dispatcher       stack.NetworkDispatcher
	inet4Address     netip.Addr
	inet6Address     netip.Addr
}

func newAwgStackDevice(opt tunPickOptions) (*awgStackDevice, error) {
	tunDevice := &awgStackDevice{
		ctx:            opt.Context,
		logger:         opt.Logger,
		mtu:            opt.MTU,
		events:         make(chan awgTun.Event, 1),
		outbound:       make(chan *stack.PacketBuffer, 256),
		packetOutbound: make(chan *buf.Buffer, 256),
		done:           make(chan struct{}),
	}
	ipStack, err := tun.NewGVisorStackWithOptions((*awgStackEndpoint)(tunDevice), stack.NICOptions{}, true)
	if err != nil {
		return nil, err
	}
	var (
		inet4Address netip.Addr
		inet6Address netip.Addr
	)
	for _, prefix := range opt.Address {
		addr := tun.AddressFromAddr(prefix.Addr())
		protoAddr := tcpip.ProtocolAddress{
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   addr,
				PrefixLen: prefix.Bits(),
			},
		}
		if prefix.Addr().Is4() {
			inet4Address = prefix.Addr()
			tunDevice.inet4Address = inet4Address
			protoAddr.Protocol = ipv4.ProtocolNumber
		} else {
			inet6Address = prefix.Addr()
			tunDevice.inet6Address = inet6Address
			protoAddr.Protocol = ipv6.ProtocolNumber
		}
		gErr := ipStack.AddProtocolAddress(tun.DefaultNIC, protoAddr, stack.AddressProperties{})
		if gErr != nil {
			return nil, E.New("parse local address ", protoAddr.AddressWithPrefix, ": ", gErr.String())
		}
	}
	// Profiles often only set IPv4 overlay (e.g. 10.8.0.3/32) while peer allows ::/0. Without a local
	// IPv6 on the gVisor NIC, DialContext to global IPv6 fails with "missing IPv6 local address".
	// Use a stable ULA (RFC 4193) so the stack can originate IPv6; tunnel carry is still governed by AWG.
	if !tunDevice.inet6Address.IsValid() {
		synth, err := netip.ParsePrefix("fd7e:a88e:7b31::1/128")
		if err != nil {
			return nil, err
		}
		a := tun.AddressFromAddr(synth.Addr())
		protoAddr := tcpip.ProtocolAddress{
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   a,
				PrefixLen: synth.Bits(),
			},
			Protocol: ipv6.ProtocolNumber,
		}
		gErr := ipStack.AddProtocolAddress(tun.DefaultNIC, protoAddr, stack.AddressProperties{})
		if gErr != nil {
			return nil, E.New("add synthetic ipv6: ", gErr.String())
		}
		tunDevice.inet6Address = synth.Addr()
		inet6Address = synth.Addr()
	}
	tunDevice.stack = ipStack
	if opt.Handler != nil {
		ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tun.NewTCPForwarder(opt.Context, ipStack, opt.Handler).HandlePacket)
		ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, tun.NewUDPForwarder(opt.Context, ipStack, opt.Handler, opt.UDPTimeout).HandlePacket)
		icmpForwarder := tun.NewICMPForwarder(opt.Context, ipStack, opt.Handler, opt.UDPTimeout)
		icmpForwarder.SetLocalAddresses(tunDevice.inet4Address, tunDevice.inet6Address)
		ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber4, icmpForwarder.HandlePacket)
		ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber6, icmpForwarder.HandlePacket)
	}
	return tunDevice, nil
}

func (w *awgStackDevice) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	addr := tcpip.FullAddress{
		NIC:  tun.DefaultNIC,
		Port: destination.Port,
		Addr: tun.AddressFromAddr(destination.Addr),
	}
	bind := tcpip.FullAddress{
		NIC: tun.DefaultNIC,
	}
	var networkProtocol tcpip.NetworkProtocolNumber
	if destination.IsIPv4() {
		if !w.inet4Address.IsValid() {
			return nil, E.New("missing IPv4 local address")
		}
		networkProtocol = header.IPv4ProtocolNumber
		bind.Addr = tun.AddressFromAddr(w.inet4Address)
	} else {
		if !w.inet6Address.IsValid() {
			return nil, E.New("missing IPv6 local address")
		}
		networkProtocol = header.IPv6ProtocolNumber
		bind.Addr = tun.AddressFromAddr(w.inet6Address)
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		tcpConn, err := dialTCPWithBind(ctx, w.stack, bind, addr, networkProtocol)
		if err != nil {
			return nil, err
		}
		return tcpConn, nil
	case N.NetworkUDP:
		udpConn, err := gonet.DialUDP(w.stack, &bind, &addr, networkProtocol)
		if err != nil {
			return nil, err
		}
		return udpConn, nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (w *awgStackDevice) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	bind := tcpip.FullAddress{
		NIC: tun.DefaultNIC,
	}
	var networkProtocol tcpip.NetworkProtocolNumber
	if destination.IsIPv4() {
		networkProtocol = header.IPv4ProtocolNumber
		bind.Addr = tun.AddressFromAddr(w.inet4Address)
	} else {
		networkProtocol = header.IPv6ProtocolNumber
		bind.Addr = tun.AddressFromAddr(w.inet6Address)
	}
	udpConn, err := gonet.DialUDP(w.stack, &bind, nil, networkProtocol)
	if err != nil {
		return nil, err
	}
	return udpConn, nil
}

func (w *awgStackDevice) Inet4Address() netip.Addr {
	return w.inet4Address
}

func (w *awgStackDevice) Inet6Address() netip.Addr {
	return w.inet6Address
}

func (w *awgStackDevice) Start() error {
	w.events <- awgTun.EventUp
	return nil
}

func (w *awgStackDevice) File() *os.File {
	return nil
}

func (w *awgStackDevice) Read(bufs [][]byte, sizes []int, offset int) (count int, err error) {
	select {
	case packet, ok := <-w.outbound:
		if !ok {
			return 0, os.ErrClosed
		}
		defer packet.DecRef()
		var copyN int
		for _, view := range packet.AsSlices() {
			copyN += copy(bufs[0][offset+copyN:], view)
		}
		sizes[0] = copyN
		return 1, nil
	case packet := <-w.packetOutbound:
		defer packet.Release()
		sizes[0] = copy(bufs[0][offset:], packet.Bytes())
		return 1, nil
	case <-w.done:
		return 0, os.ErrClosed
	}
}

func (w *awgStackDevice) Write(bufs [][]byte, offset int) (count int, err error) {
	for _, b := range bufs {
		b = b[offset:]
		if len(b) == 0 {
			continue
		}
		var networkProtocol tcpip.NetworkProtocolNumber
		switch header.IPVersion(b) {
		case header.IPv4Version:
			networkProtocol = header.IPv4ProtocolNumber
		case header.IPv6Version:
			networkProtocol = header.IPv6ProtocolNumber
		}
		packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(b),
		})
		w.dispatcher.DeliverNetworkPacket(networkProtocol, packetBuffer)
		packetBuffer.DecRef()
		count++
	}
	return
}

func (w *awgStackDevice) Flush() error {
	return nil
}

func (w *awgStackDevice) MTU() (int, error) {
	return int(w.mtu), nil
}

func (w *awgStackDevice) Name() (string, error) {
	return "sing-box", nil
}

func (w *awgStackDevice) Events() <-chan awgTun.Event {
	return w.events
}

func (w *awgStackDevice) Close() error {
	close(w.done)
	close(w.events)
	w.stack.Close()
	for _, endpoint := range w.stack.CleanupEndpoints() {
		endpoint.Abort()
	}
	w.stack.Wait()
	return nil
}

func (w *awgStackDevice) BatchSize() int {
	return 1
}

func (w *awgStackDevice) CreateDestination(metadata adapter.InboundContext, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	ctx := log.ContextWithNewID(w.ctx)
	destination, err := ping.ConnectGVisor(
		ctx, w.logger,
		metadata.Source.Addr, metadata.Destination.Addr,
		routeContext,
		w.stack,
		w.inet4Address, w.inet6Address,
		timeout,
	)
	if err != nil {
		return nil, err
	}
	w.logger.InfoContext(ctx, "linked ", metadata.Network, " connection from ", metadata.Source.AddrString(), " to ", metadata.Destination.AddrString())
	return destination, nil
}

var _ stack.LinkEndpoint = (*awgStackEndpoint)(nil)

type awgStackEndpoint awgStackDevice

func (ep *awgStackEndpoint) MTU() uint32 {
	return ep.mtu
}

func (ep *awgStackEndpoint) SetMTU(mtu uint32) {
}

func (ep *awgStackEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (ep *awgStackEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (ep *awgStackEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
}

func (ep *awgStackEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}

func (ep *awgStackEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	ep.dispatcher = dispatcher
}

func (ep *awgStackEndpoint) IsAttached() bool {
	return ep.dispatcher != nil
}

func (ep *awgStackEndpoint) Wait() {
}

func (ep *awgStackEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (ep *awgStackEndpoint) AddHeader(buffer *stack.PacketBuffer) {
}

func (ep *awgStackEndpoint) ParseHeader(ptr *stack.PacketBuffer) bool {
	return true
}

func (ep *awgStackEndpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	for _, packetBuffer := range list.AsSlice() {
		packetBuffer.IncRef()
		select {
		case <-ep.done:
			return 0, &tcpip.ErrClosedForSend{}
		case ep.outbound <- packetBuffer:
		}
	}
	return list.Len(), nil
}

func (ep *awgStackEndpoint) Close() {
}

func (ep *awgStackEndpoint) SetOnCloseAction(f func()) {
}

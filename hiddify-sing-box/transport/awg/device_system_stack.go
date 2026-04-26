//go:build with_gvisor

package awg

import (
	"context"
	"net/netip"
	"time"

	awgdevice "github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
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
	E "github.com/sagernet/sing/common/exceptions"
)

var _ tunAdapter = (*systemStackTun)(nil)

type systemStackTun struct {
	*systemTun
	ctx      context.Context
	logger   log.ContextLogger
	stack    *stack.Stack
	endpoint *awgSystemEndpoint
}

func newSystemStackDevice(opt tunPickOptions) (*systemStackTun, error) {
	system, err := newSystemTun(opt.Context, opt.Address, opt.AllowedPrefix, opt.ExcludedPrefix, opt.MTU, opt.Logger, opt.Name, opt.GSOEnabled)
	if err != nil {
		return nil, err
	}
	base, ok := system.(*systemTun)
	if !ok {
		return nil, E.New("unexpected system tun type")
	}
	endpoint := &awgSystemEndpoint{
		mtu:  opt.MTU,
		done: make(chan struct{}),
	}
	ipStack, err := tun.NewGVisorStackWithOptions(endpoint, stack.NICOptions{}, true)
	if err != nil {
		return nil, err
	}
	var inet4Address netip.Addr
	var inet6Address netip.Addr
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
			protoAddr.Protocol = ipv4.ProtocolNumber
		} else {
			inet6Address = prefix.Addr()
			protoAddr.Protocol = ipv6.ProtocolNumber
		}
		gErr := ipStack.AddProtocolAddress(tun.DefaultNIC, protoAddr, stack.AddressProperties{})
		if gErr != nil {
			return nil, E.New("parse local address ", protoAddr.AddressWithPrefix, ": ", gErr.String())
		}
	}
	if opt.Handler != nil {
		ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tun.NewTCPForwarder(opt.Context, ipStack, opt.Handler).HandlePacket)
		ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, tun.NewUDPForwarder(opt.Context, ipStack, opt.Handler, opt.UDPTimeout).HandlePacket)
		icmpForwarder := tun.NewICMPForwarder(opt.Context, ipStack, opt.Handler, opt.UDPTimeout)
		icmpForwarder.SetLocalAddresses(inet4Address, inet6Address)
		ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber4, icmpForwarder.HandlePacket)
		ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber6, icmpForwarder.HandlePacket)
	}
	return &systemStackTun{
		systemTun: base,
		ctx:       opt.Context,
		logger:    opt.Logger,
		stack:     ipStack,
		endpoint:  endpoint,
	}, nil
}

func (w *systemStackTun) SetDevice(device *awgdevice.Device) {
	w.endpoint.device = device
}

func (w *systemStackTun) Write(bufs [][]byte, offset int) (count int, err error) {
	writeBufs := make([][]byte, 0, len(bufs))
	for _, packet := range bufs {
		if !w.writeStack(packet[offset:]) {
			writeBufs = append(writeBufs, packet)
		}
	}
	if len(writeBufs) == 0 {
		return 0, nil
	}
	if w.batchTun != nil {
		return w.batchTun.BatchWrite(writeBufs, offset)
	}
	return w.systemTun.Write(writeBufs, offset)
}

func (w *systemStackTun) Close() error {
	close(w.endpoint.done)
	w.stack.Close()
	for _, endpoint := range w.stack.CleanupEndpoints() {
		endpoint.Abort()
	}
	w.stack.Wait()
	return w.systemTun.Close()
}

func (w *systemStackTun) writeStack(packet []byte) bool {
	var networkProtocol tcpip.NetworkProtocolNumber
	var destination netip.Addr
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		networkProtocol = header.IPv4ProtocolNumber
		destination = netip.AddrFrom4(header.IPv4(packet).DestinationAddress().As4())
	case header.IPv6Version:
		networkProtocol = header.IPv6ProtocolNumber
		destination = netip.AddrFrom16(header.IPv6(packet).DestinationAddress().As16())
	default:
		return false
	}
	if w.inet4.IsValid() && destination == w.inet4 {
		return false
	}
	if w.inet6.IsValid() && destination == w.inet6 {
		return false
	}
	packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	w.endpoint.dispatcher.DeliverNetworkPacket(networkProtocol, packetBuffer)
	packetBuffer.DecRef()
	return true
}

func (w *systemStackTun) CreateDestination(metadata adapter.InboundContext, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	ctx := log.ContextWithNewID(w.ctx)
	destination, err := ping.ConnectGVisor(
		ctx, w.logger,
		metadata.Source.Addr, metadata.Destination.Addr,
		routeContext,
		w.stack,
		w.inet4, w.inet6,
		timeout,
	)
	if err != nil {
		return nil, err
	}
	w.logger.InfoContext(ctx, "linked ", metadata.Network, " connection from ", metadata.Source.AddrString(), " to ", metadata.Destination.AddrString())
	return destination, nil
}

type awgSystemEndpoint struct {
	mtu        uint32
	done       chan struct{}
	device     *awgdevice.Device
	dispatcher stack.NetworkDispatcher
}

func (ep *awgSystemEndpoint) MTU() uint32 { return ep.mtu }
func (ep *awgSystemEndpoint) SetMTU(uint32) {}
func (ep *awgSystemEndpoint) MaxHeaderLength() uint16 { return 0 }
func (ep *awgSystemEndpoint) LinkAddress() tcpip.LinkAddress { return "" }
func (ep *awgSystemEndpoint) SetLinkAddress(tcpip.LinkAddress) {}
func (ep *awgSystemEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}
func (ep *awgSystemEndpoint) Attach(dispatcher stack.NetworkDispatcher) { ep.dispatcher = dispatcher }
func (ep *awgSystemEndpoint) IsAttached() bool                           { return ep.dispatcher != nil }
func (ep *awgSystemEndpoint) Wait()                                      {}
func (ep *awgSystemEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}
func (ep *awgSystemEndpoint) AddHeader(*stack.PacketBuffer) {}
func (ep *awgSystemEndpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

func (ep *awgSystemEndpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	for _, packetBuffer := range list.AsSlice() {
		destination := packetBuffer.Network().DestinationAddress()
		ep.device.InputPacket(destination.AsSlice(), packetBuffer.AsSlices())
	}
	return list.Len(), nil
}

func (ep *awgSystemEndpoint) Close()               {}
func (ep *awgSystemEndpoint) SetOnCloseAction(func()) {}

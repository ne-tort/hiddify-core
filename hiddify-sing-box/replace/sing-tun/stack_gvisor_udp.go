//go:build with_gvisor

package tun

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"os"
	"sync"
	"time"
	_ "unsafe"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/udpnat2"
)

type UDPForwarder struct {
	ctx     context.Context
	stack   *stack.Stack
	handler Handler
	udpNat  *udpnat.Service
}

func NewUDPForwarder(ctx context.Context, stack *stack.Stack, handler Handler, timeout time.Duration) *UDPForwarder {
	forwarder := &UDPForwarder{
		ctx:     ctx,
		stack:   stack,
		handler: handler,
	}
	forwarder.udpNat = udpnat.New(handler, forwarder.PreparePacketConnection, timeout, true)
	return forwarder
}

func (f *UDPForwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	source := M.SocksaddrFrom(AddrFromAddress(id.RemoteAddress), id.RemotePort)
	destination := M.SocksaddrFrom(AddrFromAddress(id.LocalAddress), id.LocalPort)
	bufferRange := pkt.Data().AsRange()
	bufferSlices := make([][]byte, 0, 8)
	rangeIterate(bufferRange, func(view *buffer.View) {
		bufferSlices = append(bufferSlices, view.AsSlice())
	})
	f.udpNat.NewPacket(bufferSlices, source, destination, pkt)
	return true
}

//go:linkname rangeIterate github.com/sagernet/gvisor/pkg/tcpip/stack.Range.iterate
func rangeIterate(r stack.Range, fn func(*buffer.View))

func (f *UDPForwarder) PreparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	_, pErr := f.handler.PrepareConnection(N.NetworkUDP, source, destination, nil, 0)
	if pErr != nil {
		if !errors.Is(pErr, ErrDrop) {
			gWriteUnreachable(f.stack, userData.(*stack.PacketBuffer))
		}
		return false, nil, nil, nil
	}
	var sourceNetwork tcpip.NetworkProtocolNumber
	if source.Addr.Is4() {
		sourceNetwork = header.IPv4ProtocolNumber
	} else {
		sourceNetwork = header.IPv6ProtocolNumber
	}
	writer := &UDPBackWriter{
		stack:         f.stack,
		packet:        userData.(*stack.PacketBuffer).IncRef(),
		source:        AddressFromAddr(source.Addr),
		sourcePort:    source.Port,
		sourceNetwork: sourceNetwork,
	}
	return true, f.ctx, writer, nil
}

type UDPBackWriter struct {
	access        sync.Mutex
	stack         *stack.Stack
	packet        *stack.PacketBuffer
	source        tcpip.Address
	sourcePort    uint16
	sourceNetwork tcpip.NetworkProtocolNumber
	// lastRemote* is the last onward destination passed to WritePacket (MASQUE egress peer).
	lastRemote     tcpip.Address
	lastRemotePort uint16
}

func (w *UDPBackWriter) HandshakeSuccess() error {
	w.access.Lock()
	defer w.access.Unlock()
	if w.packet != nil {
		w.packet.DecRef()
		w.packet = nil
	}
	return nil
}

func (w *UDPBackWriter) HandshakeFailure(err error) error {
	w.access.Lock()
	defer w.access.Unlock()
	if w.packet == nil {
		return os.ErrInvalid
	}
	wErr := gWriteUnreachable(w.stack, w.packet)
	w.packet.DecRef()
	w.packet = nil
	return wErr
}

// WriteUDPPortUnreachable injects ICMP port-unreachable for the flow bound to this writer
// (MASQUE CONNECT-UDP empty DATAGRAM after handshake success).
func (w *UDPBackWriter) WriteUDPPortUnreachable(remote M.Socksaddr) error {
	w.access.Lock()
	defer w.access.Unlock()
	if w.packet != nil {
		pkt := w.packet.IncRef()
		defer pkt.DecRef()
		return gWriteUnreachable(w.stack, pkt)
	}
	if !remote.IsValid() && w.lastRemote.Len() > 0 {
		remote = M.SocksaddrFrom(AddrFromAddress(w.lastRemote), w.lastRemotePort)
	}
	if !remote.IsIP() {
		return E.Cause(os.ErrInvalid, "invalid remote for icmp feedback")
	}
	return w.writeSyntheticPortUnreachable(remote)
}

func (w *UDPBackWriter) writeSyntheticPortUnreachable(remote M.Socksaddr) error {
	remoteAddr := AddressFromAddr(remote.Addr)
	remotePort := remote.Port
	payload := buffer.MakeWithData(nil)
	defer payload.Release()
	reserveHdr := header.IPv6MinimumSize
	if w.sourceNetwork == header.IPv4ProtocolNumber {
		reserveHdr = header.IPv4MinimumSize
	}
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + reserveHdr,
		Payload:            payload,
	})
	defer packet.DecRef()
	packet.TransportProtocolNumber = header.UDPProtocolNumber
	udpHdr := header.UDP(packet.TransportHeader().Push(header.UDPMinimumSize))
	udpHdr.Encode(&header.UDPFields{
		SrcPort: w.sourcePort,
		DstPort: remotePort,
		Length:  header.UDPMinimumSize,
	})
	packet.NetworkProtocolNumber = w.sourceNetwork
	if w.sourceNetwork == header.IPv4ProtocolNumber {
		ipv4Hdr := header.IPv4(packet.NetworkHeader().Push(header.IPv4MinimumSize))
		totalLen := uint16(header.IPv4MinimumSize + header.UDPMinimumSize)
		ipv4Hdr.Encode(&header.IPv4Fields{
			TotalLength: totalLen,
			ID:          0,
			TTL:         64,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     w.source,
			DstAddr:     remoteAddr,
		})
	} else {
		ipv6Hdr := header.IPv6(packet.NetworkHeader().Push(header.IPv6MinimumSize))
		ipv6Hdr.Encode(&header.IPv6Fields{
			PayloadLength:     header.UDPMinimumSize,
			TransportProtocol: header.UDPProtocolNumber,
			HopLimit:          64,
			SrcAddr:           w.source,
			DstAddr:           remoteAddr,
		})
	}
	return gWriteUnreachable(w.stack, packet)
}

func (w *UDPBackWriter) WritePacket(packetBuffer *buf.Buffer, destination M.Socksaddr) error {
	if !destination.IsIP() {
		return E.Cause(os.ErrInvalid, "invalid destination")
	}
	w.access.Lock()
	w.lastRemote = AddressFromAddr(destination.Addr)
	w.lastRemotePort = destination.Port
	w.access.Unlock()
	if destination.IsIPv4() && w.sourceNetwork == header.IPv6ProtocolNumber {
		destination = M.SocksaddrFrom(netip.AddrFrom16(destination.Addr.As16()), destination.Port)
	} else if destination.IsIPv6() && (w.sourceNetwork == header.IPv4ProtocolNumber) {
		return E.New("send IPv6 packet to IPv4 connection")
	}

	defer packetBuffer.Release()

	route, err := w.stack.FindRoute(
		DefaultNIC,
		AddressFromAddr(destination.Addr),
		w.source,
		w.sourceNetwork,
		false,
	)
	if err != nil {
		return gonet.TranslateNetstackError(err)
	}
	defer route.Release()

	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + int(route.MaxHeaderLength()),
		Payload:            buffer.MakeWithData(packetBuffer.Bytes()),
	})
	defer packet.DecRef()

	packet.TransportProtocolNumber = header.UDPProtocolNumber
	udpHdr := header.UDP(packet.TransportHeader().Push(header.UDPMinimumSize))
	pLen := uint16(packet.Size())
	udpHdr.Encode(&header.UDPFields{
		SrcPort: destination.Port,
		DstPort: w.sourcePort,
		Length:  pLen,
	})

	if route.RequiresTXTransportChecksum() && w.sourceNetwork == header.IPv6ProtocolNumber {
		xsum := udpHdr.CalculateChecksum(checksum.Combine(
			route.PseudoHeaderChecksum(header.UDPProtocolNumber, pLen),
			packet.Data().Checksum(),
		))
		if xsum != math.MaxUint16 {
			xsum = ^xsum
		}
		udpHdr.SetChecksum(xsum)
	}

	err = route.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.UDPProtocolNumber,
		TTL:      route.DefaultTTL(),
		TOS:      0,
	}, packet)
	if err != nil {
		route.Stats().UDP.PacketSendErrors.Increment()
		return gonet.TranslateNetstackError(err)
	}

	route.Stats().UDP.PacketsSent.Increment()
	return nil
}

func gWriteUnreachable(gStack *stack.Stack, packet *stack.PacketBuffer) error {
	if packet.NetworkProtocolNumber == header.IPv4ProtocolNumber {
		return gonet.TranslateNetstackError(gStack.NetworkProtocolInstance(header.IPv4ProtocolNumber).(stack.RejectIPv4WithHandler).SendRejectionError(packet, stack.RejectIPv4WithICMPPortUnreachable, true))
	} else {
		return gonet.TranslateNetstackError(gStack.NetworkProtocolInstance(header.IPv6ProtocolNumber).(stack.RejectIPv6WithHandler).SendRejectionError(packet, stack.RejectIPv6WithICMPPortUnreachable, true))
	}
}

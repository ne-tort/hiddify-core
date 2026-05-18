package tun

import (
	"os"
	"syscall"

	"github.com/sagernet/sing-tun/internal/gtcpip/checksum"
	"github.com/sagernet/sing-tun/internal/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// UDPPortUnreachableFeedback injects ICMP destination-unreachable (port) into the TUN stack
// for an established UDP flow (MASQUE CONNECT-UDP bench dig parity).
type UDPPortUnreachableFeedback interface {
	WriteUDPPortUnreachable(remote M.Socksaddr) error
}

func writeIPv4ICMPPortUnreachable(tun Tun, frontHeadroom int, mtu int, originalIPHeader []byte) error {
	if len(originalIPHeader) < header.IPv4MinimumSize {
		return os.ErrInvalid
	}
	ipHdr := header.IPv4(originalIPHeader)
	if mtu <= 0 {
		mtu = 1500
	}
	const maxIPData = header.IPv4MinimumProcessableDatagramSize - header.IPv4MinimumSize
	if mtu > maxIPData {
		mtu = maxIPData
	}
	available := mtu - header.ICMPv4MinimumSize
	if available < len(ipHdr)+header.ICMPv4MinimumErrorPayloadSize {
		return nil
	}
	payload := ipHdr
	if len(payload) > available {
		payload = payload[:available]
	}
	newPacket := buf.NewSize(frontHeadroom + header.IPv4MinimumSize + header.ICMPv4MinimumSize + len(payload))
	defer newPacket.Release()
	newPacket.Resize(frontHeadroom, header.IPv4MinimumSize+header.ICMPv4MinimumSize+len(payload))
	newIPHdr := header.IPv4(newPacket.Bytes())
	newIPHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(newPacket.Len()),
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     ipHdr.DestinationAddr(),
		DstAddr:     ipHdr.SourceAddr(),
	})
	newIPHdr.SetChecksum(^newIPHdr.CalculateChecksum())
	icmpHdr := header.ICMPv4(newIPHdr.Payload())
	icmpHdr.SetType(header.ICMPv4DstUnreachable)
	icmpHdr.SetCode(header.ICMPv4PortUnreachable)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], checksum.Checksum(ipHdr.Payload(), 0)))
	copy(icmpHdr.Payload(), payload)
	if PacketOffset > 0 {
		newPacket.ExtendHeader(PacketOffset)[3] = syscall.AF_INET
	} else {
		newPacket.Advance(-frontHeadroom)
	}
	return common.Error(tun.Write(newPacket.Bytes()))
}

func writeIPv6ICMPPortUnreachable(tun Tun, frontHeadroom int, mtu int, originalIPHeader []byte) error {
	if len(originalIPHeader) < header.IPv6MinimumSize {
		return os.ErrInvalid
	}
	ipHdr := header.IPv6(originalIPHeader)
	if mtu <= 0 {
		mtu = 1500
	}
	const maxIPv6Data = header.IPv6MinimumMTU - header.IPv6FixedHeaderSize
	if mtu > maxIPv6Data {
		mtu = maxIPv6Data
	}
	available := mtu - header.ICMPv6ErrorHeaderSize
	if available < len(ipHdr)+header.ICMPv6DstUnreachableMinimumSize {
		return nil
	}
	payload := ipHdr
	if len(payload) > available {
		payload = payload[:available]
	}
	newPacket := buf.NewSize(frontHeadroom + header.IPv6MinimumSize + header.ICMPv6DstUnreachableMinimumSize + len(payload))
	defer newPacket.Release()
	newPacket.Resize(frontHeadroom, header.IPv6MinimumSize+header.ICMPv6DstUnreachableMinimumSize+len(payload))
	newIPHdr := header.IPv6(newPacket.Bytes())
	newIPHdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.ICMPv6DstUnreachableMinimumSize + len(payload)),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		SrcAddr:           ipHdr.DestinationAddr(),
		DstAddr:           ipHdr.SourceAddr(),
	})
	icmpHdr := header.ICMPv6(newIPHdr.Payload())
	icmpHdr.SetType(header.ICMPv6DstUnreachable)
	icmpHdr.SetCode(header.ICMPv6PortUnreachable)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHdr,
		Src:    newIPHdr.SourceAddressSlice(),
		Dst:    newIPHdr.DestinationAddressSlice(),
	}))
	copy(icmpHdr.Payload(), payload)
	if PacketOffset > 0 {
		PacketFillHeader(newPacket.ExtendHeader(PacketOffset), header.IPv6Version)
	} else {
		newPacket.Advance(-frontHeadroom)
	}
	return common.Error(tun.Write(newPacket.Bytes()))
}

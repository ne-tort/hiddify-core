package connectip

import cipframe "github.com/sagernet/sing-box/transport/masque/connectip/frame"

// Root re-exports from connectip/frame during W-IP-1 subdir migration (IP-1-PR1).

var (
	IPv4TCPAckOnly              = cipframe.IPv4TCPAckOnly
	IPv4TCPHasPayload           = cipframe.IPv4TCPHasPayload
	IPv4TCPIngressWakeCandidate = cipframe.IPv4TCPIngressWakeCandidate
	TCPIngressFastPath          = cipframe.TCPIngressFastPath

	IPv4HeaderIndicatesFragmentation  = cipframe.IPv4HeaderIndicatesFragmentation
	ParseIPv4UDPPacketOffsets         = cipframe.ParseIPv4UDPPacketOffsets
	IPv4UDPBridgeDstPort              = cipframe.IPv4UDPBridgeDstPort
	ParseIPv4UDPPacket                = cipframe.ParseIPv4UDPPacket
	BuildIPv4UDPPacket                = cipframe.BuildIPv4UDPPacket
	BuildIPv4UDPPacketInplace         = cipframe.BuildIPv4UDPPacketInplace
	BuildIPv4UDPPacketInplaceV4       = cipframe.BuildIPv4UDPPacketInplaceV4
	NewIPv4UDPHeaderTemplate          = cipframe.NewIPv4UDPHeaderTemplate
	BuildIPv4UDPPacketInplaceHeaderV4 = cipframe.BuildIPv4UDPPacketInplaceHeaderV4
	IPv4HeaderChecksum                = cipframe.IPv4HeaderChecksum
	ParseICMPPortUnreachablePeer      = cipframe.ParseICMPPortUnreachablePeer
)

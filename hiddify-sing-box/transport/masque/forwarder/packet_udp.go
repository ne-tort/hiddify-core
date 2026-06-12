package forwarder

import (
	"net/netip"

	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
)

func buildIPv4UDPPacket(src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16, payload []byte) ([]byte, error) {
	return mcip.BuildIPv4UDPPacket(src, srcPort, dst, dstPort, payload)
}

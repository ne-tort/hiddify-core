package quic

import (
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	masqueDatagramContextPrefixLen = 1
	ipv4TCPProtocolNumber          = 6
	ipv4MinHeaderLen               = 20
	tcpMinHeaderLen                = 20
)

func masqueIPv4TCPHasPayload(pkt []byte) bool {
	if len(pkt) < ipv4MinHeaderLen || pkt[0]>>4 != 4 || pkt[9] != ipv4TCPProtocolNumber {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+tcpMinHeaderLen > len(pkt) {
		return false
	}
	doff := int(pkt[ihl+12]>>4) * 4
	if doff < tcpMinHeaderLen || ihl+doff > len(pkt) {
		return false
	}
	return len(pkt) > ihl+doff
}

func masqueDatagramFrameHasTCPPayload(f *wire.DatagramFrame) bool {
	if f == nil || len(f.Data) == 0 {
		return false
	}
	_, n, err := quicvarint.Parse(f.Data)
	if err != nil || n <= 0 || n+masqueDatagramContextPrefixLen >= len(f.Data) {
		return false
	}
	return masqueIPv4TCPHasPayload(f.Data[n+masqueDatagramContextPrefixLen:])
}

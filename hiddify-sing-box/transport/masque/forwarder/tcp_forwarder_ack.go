package forwarder

import (
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

func (f *packetForwarder) coalesceQueuedAckOnly(first []byte) []byte {
	flow, ok := ackOnlyFlow(first)
	if !ok {
		return first
	}
	newest := first
	for {
		select {
		case next := <-f.writeCh:
			f.o.WriteQueueMetrics.noteDequeued()
			if nf, ok := ackOnlyFlow(next); ok && nf == flow {
				returnPacket(newest)
				newest = next
				continue
			}
			_ = f.sendPacketNow(newest)
			returnPacket(newest)
			return next
		default:
			return newest
		}
	}
}

func ackOnlyFlow(pkt []byte) (tcp4Tuple, bool) {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 || pkt[9] != uint8(header.TCPProtocolNumber) {
		return tcp4Tuple{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+header.TCPMinimumSize > len(pkt) {
		return tcp4Tuple{}, false
	}
	tc := header.TCP(pkt[ihl:])
	if tc.Flags() != header.TCPFlagAck {
		return tcp4Tuple{}, false
	}
	doff := int(pkt[ihl+12]>>4) * 4
	if doff < header.TCPMinimumSize || ihl+doff > len(pkt) {
		return tcp4Tuple{}, false
	}
	if len(pkt)-ihl-doff > 0 {
		return tcp4Tuple{}, false
	}
	return tcp4Tuple{
		srcAddr: header.IPv4(pkt).DestinationAddress(),
		dstAddr: header.IPv4(pkt).SourceAddress(),
		srcPort: tc.DestinationPort(),
		dstPort: tc.SourcePort(),
	}, true
}

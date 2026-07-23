package forwarder

import (
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/sing-box/transport/masque/connectip/relaystats"
)

// coalesceQueuedAckOnly collapses same-flow ACK-only segments already queued on
// writeCh. Also drains up to ackCoalesceScanMax other ACK-only flows by keeping
// the newest per-flow (re-queue order: other flows' latest, then leftover non-ACK).
// Under iperf -P≥3, A/B/C ACK interleave previously defeated same-flow-only coalesce.
const ackCoalesceScanMax = 64

func (f *packetForwarder) coalesceQueuedAckOnly(first []byte) (newest []byte, leftover []byte) {
	flow, ok := ackOnlyFlow(first)
	if !ok {
		return first, nil
	}
	newest = first
	type held struct {
		flow tcp4Tuple
		pkt  []byte
	}
	var others []held
	for scanned := 0; scanned < ackCoalesceScanMax; scanned++ {
		select {
		case next := <-f.writeCh:
			f.o.WriteQueueMetrics.noteDequeued()
			if nf, ok := ackOnlyFlow(next); ok {
				if nf == flow {
					returnPacket(newest)
					newest = next
					continue
				}
				replaced := false
				for i := range others {
					if others[i].flow == nf {
						returnPacket(others[i].pkt)
						others[i].pkt = next
						replaced = true
						break
					}
				}
				if !replaced {
					others = append(others, held{flow: nf, pkt: next})
				}
				continue
			}
			// Non-ACK: re-queue coalesced other-flow ACKs behind this leftover via
			// caller sending newest first; push others back on writeCh.
			for i := len(others) - 1; i >= 0; i-- {
				select {
				case f.writeCh <- others[i].pkt:
					f.o.WriteQueueMetrics.noteEnqueued()
				default:
					// Prefer keeping newest primary ACK on wire; drop overflow others.
					returnPacket(others[i].pkt)
					relaystats.RecordS2CAckAdmitDrop()
				}
			}
			return newest, next
		default:
			for i := len(others) - 1; i >= 0; i-- {
				select {
				case f.writeCh <- others[i].pkt:
					f.o.WriteQueueMetrics.noteEnqueued()
				default:
					returnPacket(others[i].pkt)
					relaystats.RecordS2CAckAdmitDrop()
				}
			}
			return newest, nil
		}
	}
	for i := len(others) - 1; i >= 0; i-- {
		select {
		case f.writeCh <- others[i].pkt:
			f.o.WriteQueueMetrics.noteEnqueued()
		default:
			returnPacket(others[i].pkt)
			relaystats.RecordS2CAckAdmitDrop()
		}
	}
	return newest, nil
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

// wireTCPPayloadLen returns TCP payload length for IPv4 TCP packets (0 if not).
func wireTCPPayloadLen(pkt []byte) int {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 || pkt[9] != uint8(header.TCPProtocolNumber) {
		return 0
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+header.TCPMinimumSize > len(pkt) {
		return 0
	}
	doff := int(pkt[ihl+12]>>4) * 4
	if doff < header.TCPMinimumSize || ihl+doff > len(pkt) {
		return 0
	}
	return len(pkt) - ihl - doff
}

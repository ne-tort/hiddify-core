package netstack

import cipframe "github.com/sagernet/sing-box/transport/masque/connectip/frame"

// egressBatch coalesces ACK-only frames per flow for one link-endpoint drain iteration.
type egressBatch struct {
	pendingAck map[cipframe.TCP4Flow][]byte
}

func newEgressBatch() *egressBatch {
	return &egressBatch{pendingAck: make(map[cipframe.TCP4Flow][]byte)}
}

func (b *egressBatch) flushAck(flow cipframe.TCP4Flow) []byte {
	pkt, ok := b.pendingAck[flow]
	if !ok {
		return nil
	}
	delete(b.pendingAck, flow)
	return pkt
}

func (b *egressBatch) flushAllAcks() [][]byte {
	out := make([][]byte, 0, len(b.pendingAck))
	for flow := range b.pendingAck {
		if pkt := b.flushAck(flow); pkt != nil {
			out = append(out, pkt)
		}
	}
	return out
}

func (b *egressBatch) coalesceAck(payload []byte) bool {
	if !cipframe.IPv4TCPAckOnly(payload) {
		return false
	}
	flow, ok := cipframe.TCP4FlowFromIPv4(payload)
	if !ok {
		return false
	}
	if prev, ok := b.pendingAck[flow]; ok {
		returnOutboundBuf(prev)
	}
	b.pendingAck[flow] = payload
	return true
}

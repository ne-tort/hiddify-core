package frame

import (
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

// IPv4TCPAckOnly reports an inbound IPv4 TCP segment with ACK set and no payload.
func IPv4TCPAckOnly(pkt []byte) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != uint8(header.TCPProtocolNumber) {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+header.TCPMinimumSize > len(pkt) {
		return false
	}
	doff := int(pkt[ihl+12]>>4) * 4
	if doff < header.TCPMinimumSize || ihl+doff > len(pkt) {
		return false
	}
	if len(pkt) > ihl+doff {
		return false
	}
	return pkt[ihl+13]&0x10 != 0
}

// IPv4TCPHasPayload reports whether pkt carries TCP payload bytes after the header.
func IPv4TCPHasPayload(pkt []byte) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != uint8(header.TCPProtocolNumber) {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+header.TCPMinimumSize > len(pkt) {
		return false
	}
	doff := int(pkt[ihl+12]>>4) * 4
	if doff < header.TCPMinimumSize || ihl+doff > len(pkt) {
		return false
	}
	return len(pkt) > ihl+doff
}

// IPv4TCPIngressWakeCandidate is true for inbound TCP ACK-only (upload ACK-clock from server)
// and for segments carrying payload (download DATA → client must emit ACKs on QUIC egress).
func IPv4TCPIngressWakeCandidate(pkt []byte) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != uint8(header.TCPProtocolNumber) {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+header.TCPMinimumSize > len(pkt) {
		return false
	}
	doff := int(pkt[ihl+12]>>4) * 4
	if doff < header.TCPMinimumSize || ihl+doff > len(pkt) {
		return false
	}
	if len(pkt) > ihl+doff {
		return true
	}
	return pkt[ihl+13]&0x10 != 0
}

// TCPIngressFastPath gates the early TCP inject path when UDP bridge subscribers are absent.
func TCPIngressFastPath(pkt []byte, udpSubsEmpty bool, hasIngressNetstack bool, installInflight bool) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != uint8(header.TCPProtocolNumber) {
		return false
	}
	if !udpSubsEmpty {
		return false
	}
	return hasIngressNetstack || installInflight
}

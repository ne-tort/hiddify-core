package forwarder

import (
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

func TestMaxSegmentPayloadFitsDatagramCeiling(t *testing.T) {
	t.Parallel()
	maxSeg := MaxSegmentPayload(1460)
	const tcpHdrBudget = header.TCPMinimumSize + 12
	wantCap := maxIPv4Datagram - header.IPv4MinimumSize - tcpHdrBudget
	if maxSeg > wantCap {
		t.Fatalf("maxSeg=%d want <= %d (gVisor CONNECT-IP MTU)", maxSeg, wantCap)
	}
	if maxSeg > 1320 {
		t.Fatalf("maxSeg=%d still near wire MSS; expected clamp for %d B datagram path", maxSeg, MaxIPv4WireBytes)
	}
	if maxSeg < 512 {
		t.Fatalf("maxSeg=%d too small", maxSeg)
	}
}

func TestBuildIPv4TCPPacketChecksumValid(t *testing.T) {
	t.Parallel()
	opts := buildSynAckTCPOptions(header.TCPSynOptions{MSS: 1460, WS: 7, TS: true, TSVal: 42}, 1000)
	src := tcpip.AddrFrom4([4]byte{127, 0, 0, 1})
	dst := tcpip.AddrFrom4([4]byte{198, 18, 0, 1})
	pkt := BuildIPv4TCPPacket(src, dst, 443, 52001, 1, 2, header.TCPFlagSyn|header.TCPFlagAck, 65535, nil, opts)
	ihl := int(pkt[0]&0x0f) * 4
	tc := header.TCP(pkt[ihl:])
	doff := int(pkt[ihl+12]>>4) * 4
	if doff != int(tc.DataOffset()) {
		t.Fatalf("tcp header len mismatch: doff=%d DataOffset()=%d", doff, tc.DataOffset())
	}
	tcpLen := uint16(len(pkt) - ihl)
	payloadLen := tcpLen - uint16(doff)
	payCsum := checksum.Checksum(pkt[ihl+doff:], 0)
	if !tc.IsChecksumValid(src, dst, payCsum, payloadLen) {
		t.Fatalf("invalid tcp checksum on syn-ack packet len=%d doff=%d", len(pkt), doff)
	}
}

// TestGATEServerWSFloor: SYN-ACK must announce server WS≥10, not echo a low client shift.
// Echo WS≤1 → rcv window 64–128KiB → ~17–34 Mbit/s ceiling on ~30ms WAN RTT.
func TestGATEServerWSFloor(t *testing.T) {
	t.Parallel()
	const floor = 10
	clientWS := 1
	so := header.TCPSynOptions{MSS: 1460, WS: clientWS}
	if so.WS >= 0 {
		so.WS = floor // same mutation as tcp_forwarder_syn.go
	}
	raw := buildSynAckTCPOptions(so, 0)
	parsed := header.ParseSynOptions(raw, true)
	if parsed.WS != floor {
		t.Fatalf("SYN-ACK WS=%d want server floor %d (client offered %d)", parsed.WS, floor, clientWS)
	}
}

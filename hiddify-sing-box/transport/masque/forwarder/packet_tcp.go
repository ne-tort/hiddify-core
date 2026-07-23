package forwarder

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

const (
	maxIPv4Datagram       = MaxIPv4WireBytes
	remoteReadBuf         = 256 << 10
	remoteWriteBuf        = 2 << 20
	remoteFlushBatch      = 64 * 1024
	// Residual C2S (iperf results JSON ~1–4KiB) sits below remoteFlushBatch and
	// above the ≤512 immediate flush — without idle flush it never reaches the
	// backend and host-TUN iperf -P≥3 hangs on "unable to receive results".
	remoteIdleFlushAfter   = 1 * time.Millisecond
	writeQueueDepth        = 2048
	downloadQueueDepth     = 8192
	writePacketMaxPersist  = 128
	kernelBuf              = 16 << 20
	icmpRelayMax           = 8
)

// MaxSegmentPayload caps one CONNECT-IP TCP segment payload (MSS minus timestamp options).
func MaxSegmentPayload(clientMSS uint16) int {
	maxSeg := int(clientMSS)
	if maxSeg <= 0 {
		maxSeg = 1460
	}
	if maxSeg > 12 {
		maxSeg -= 12
	}
	const tcpHdrBudget = header.TCPMinimumSize + 12
	if cap := maxIPv4Datagram - header.IPv4MinimumSize - tcpHdrBudget; cap > 0 && maxSeg > cap {
		maxSeg = cap
	}
	if maxSeg < 512 {
		maxSeg = 512
	}
	return maxSeg
}

func tuneRemote(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(kernelBuf)
		_ = tc.SetWriteBuffer(kernelBuf)
	}
}

// BuildSynAckTCPOptions builds SYN-ACK TCP options from parsed SYN options.
// serverTS is the forwarder send timestamp for this session (RFC 7323 PAWS parity); 0 picks random.
func BuildSynAckTCPOptions(so header.TCPSynOptions, serverTS uint32) []byte {
	return buildSynAckTCPOptions(so, serverTS)
}

func newForwarderSendTimestamp() uint32 {
	var ts [4]byte
	_, _ = rand.Read(ts[:])
	v := binary.BigEndian.Uint32(ts[:])
	if v == 0 {
		v = 1
	}
	return v
}

func buildSynAckTCPOptions(so header.TCPSynOptions, serverTS uint32) []byte {
	var out []byte
	mss := so.MSS
	if mss == 0 || mss > 1460 {
		mss = 1460
	}
	out = append(out, header.TCPOptionMSS, header.TCPOptionMSSLength, byte(mss>>8), byte(mss))
	if so.WS >= 0 {
		shift := so.WS
		if shift > 14 {
			shift = 14
		}
		out = append(out, header.TCPOptionWS, header.TCPOptionWSLength, byte(shift))
		out = append(out, header.TCPOptionNOP)
	}
	if so.SACKPermitted {
		out = append(out, header.TCPOptionSACKPermitted, header.TCPOptionSackPermittedLength)
	}
	if so.TS {
		if serverTS == 0 {
			serverTS = newForwarderSendTimestamp()
		}
		out = append(out, header.TCPOptionNOP, header.TCPOptionNOP)
		out = append(out, header.TCPOptionTS, header.TCPOptionTSLength)
		var ts [8]byte
		binary.BigEndian.PutUint32(ts[:4], serverTS)
		binary.BigEndian.PutUint32(ts[4:], so.TSVal)
		out = append(out, ts[:]...)
	}
	for len(out)%4 != 0 {
		out = append(out, header.TCPOptionNOP)
	}
	return out
}

func randomISN() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	x := binary.BigEndian.Uint32(b[:])
	if x == 0 {
		x = 1
	}
	return x, nil
}

// BuildIPv4TCPPacket builds a full IPv4/TCP datagram (exported for unit tests).
func BuildIPv4TCPPacket(
	srcAddr, dstAddr tcpip.Address,
	srcPort, dstPort uint16,
	seq, ack uint32,
	flags header.TCPFlags,
	window uint16,
	payload []byte,
	tcpOpts []byte,
) []byte {
	return buildIPv4TCPPacket(srcAddr, dstAddr, srcPort, dstPort, seq, ack, flags, window, payload, tcpOpts)
}

func buildIPv4TCPPacket(
	srcAddr, dstAddr tcpip.Address,
	srcPort, dstPort uint16,
	seq, ack uint32,
	flags header.TCPFlags,
	window uint16,
	payload []byte,
	tcpOpts []byte,
) []byte {
	tcpHdrLen := header.TCPMinimumSize + len(tcpOpts)
	if tcpHdrLen%4 != 0 {
		pad := 4 - (tcpHdrLen % 4)
		tcpOpts = append(append([]byte(nil), tcpOpts...), bytesRepeat(header.TCPOptionNOP, pad)...)
		tcpHdrLen = header.TCPMinimumSize + len(tcpOpts)
	}
	totalLen := header.IPv4MinimumSize + tcpHdrLen + len(payload)
	pkt := borrowPacket(totalLen)
	iph := header.IPv4(pkt[:header.IPv4MinimumSize])
	iph.Encode(&header.IPv4Fields{
		TOS:            0,
		TotalLength:    uint16(totalLen),
		ID:             nextIPv4PacketID(),
		TTL:            64,
		Protocol:       uint8(header.TCPProtocolNumber),
		Checksum:       0,
		SrcAddr:        srcAddr,
		DstAddr:        dstAddr,
		Flags:          0,
		FragmentOffset: 0,
	})
	iph.SetChecksum(^iph.CalculateChecksum())

	tcpOff := header.IPv4MinimumSize
	tc := header.TCP(pkt[tcpOff:])
	copy(tc[header.TCPMinimumSize:], tcpOpts)
	tf := header.TCPFields{
		SrcPort:       srcPort,
		DstPort:       dstPort,
		SeqNum:        seq,
		AckNum:        ack,
		DataOffset:    uint8(tcpHdrLen),
		Flags:         flags,
		WindowSize:    window,
		Checksum:      0,
		UrgentPointer: 0,
	}
	tc.Encode(&tf)
	payCsum := checksum.Checksum(payload, 0)
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcAddr, dstAddr, uint16(tcpHdrLen)+uint16(len(payload)))
	xsum = checksum.Combine(xsum, payCsum)
	tc.SetChecksum(^tc.CalculateChecksum(xsum))
	copy(pkt[tcpOff+tcpHdrLen:], payload)
	return pkt
}

func bytesRepeat(b byte, n int) []byte {
	if n <= 0 {
		return nil
	}
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

var ipv4ID atomic.Uint32

func nextIPv4PacketID() uint16 {
	for {
		v := ipv4ID.Add(1)
		if v != 0 {
			return uint16(v)
		}
	}
}

func init() {
	var b [4]byte
	_, _ = rand.Read(b[:])
	ipv4ID.Store(binary.BigEndian.Uint32(b[:]))
}

// parseAckWireMeta records patch offsets for ACK-only wire templates.
func parseAckWireMeta(pkt []byte) ackWireMeta {
	meta := ackWireMeta{tsValOff: -1, tsEchoOff: -1, ipv4IDOff: -1}
	if len(pkt) >= header.IPv4MinimumSize && pkt[0]>>4 == 4 {
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < header.IPv4MinimumSize || ihl+header.TCPMinimumSize > len(pkt) {
			return meta
		}
		meta.isIPv4 = true
		meta.ipv4IDOff = 4
		meta.tcpOff = ihl
		ip := header.IPv4(pkt)
		meta.srcAddr = ip.SourceAddress()
		meta.dstAddr = ip.DestinationAddress()
	} else if len(pkt) >= header.IPv6MinimumSize && pkt[0]>>4 == 6 {
		meta.tcpOff = header.IPv6MinimumSize
		if meta.tcpOff+header.TCPMinimumSize > len(pkt) {
			return meta
		}
		ip := header.IPv6(pkt)
		meta.srcAddr = ip.SourceAddress()
		meta.dstAddr = ip.DestinationAddress()
	} else {
		return meta
	}
	tc := header.TCP(pkt[meta.tcpOff:])
	meta.tcpLen = int(tc.DataOffset())
	if meta.tcpOff+meta.tcpLen > len(pkt) {
		return ackWireMeta{tsValOff: -1, tsEchoOff: -1, ipv4IDOff: -1}
	}
	meta.seqOff = meta.tcpOff + 4
	meta.ackOff = meta.tcpOff + 8
	opts := pkt[meta.tcpOff+header.TCPMinimumSize : meta.tcpOff+meta.tcpLen]
	for i := 0; i < len(opts); {
		switch opts[i] {
		case header.TCPOptionEOL:
			return meta
		case header.TCPOptionNOP:
			i++
		case header.TCPOptionTS:
			if i+1 < len(opts) && opts[i+1] == header.TCPOptionTSLength && i+10 <= len(opts) {
				base := meta.tcpOff + header.TCPMinimumSize + i + 2
				meta.tsValOff = base
				meta.tsEchoOff = base + 4
			}
			return meta
		default:
			if i+1 >= len(opts) {
				return meta
			}
			l := int(opts[i+1])
			if l < 2 {
				return meta
			}
			i += l
		}
	}
	return meta
}

// patchAckWireChecksums refreshes IPv4 ID + L4 checksum on a cloned ACK template.
func patchAckWireChecksums(pkt []byte, m ackWireMeta) {
	if m.tcpOff == 0 || m.tcpLen < header.TCPMinimumSize {
		return
	}
	if m.isIPv4 && m.ipv4IDOff >= 0 {
		binary.BigEndian.PutUint16(pkt[m.ipv4IDOff:], nextIPv4PacketID())
		iph := header.IPv4(pkt)
		iph.SetChecksum(0)
		iph.SetChecksum(^iph.CalculateChecksum())
	}
	tc := header.TCP(pkt[m.tcpOff:])
	tc.SetChecksum(0)
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, m.srcAddr, m.dstAddr, uint16(m.tcpLen))
	tc.SetChecksum(^tc.CalculateChecksum(xsum))
}

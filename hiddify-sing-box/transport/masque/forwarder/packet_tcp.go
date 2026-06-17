package forwarder

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync/atomic"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

const (
	maxIPv4Datagram       = DefaultDatagramCeilingMax - DatagramSlack
	remoteReadBuf         = 8 << 20
	remoteWriteBuf        = 2 << 20
	remoteFlushBatch      = 64 * 1024
	writeQueueDepth       = 512
	downloadQueueDepth    = 8192
	writePacketMaxPersist = 128
	kernelBuf             = 16 << 20
	icmpRelayMax          = 8
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
func BuildSynAckTCPOptions(so header.TCPSynOptions) []byte {
	return buildSynAckTCPOptions(so)
}

func buildSynAckTCPOptions(so header.TCPSynOptions) []byte {
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
		out = append(out, header.TCPOptionNOP, header.TCPOptionNOP)
		out = append(out, header.TCPOptionTS, header.TCPOptionTSLength)
		var ts [8]byte
		_, _ = rand.Read(ts[:])
		binary.BigEndian.PutUint32(ts[:4], binary.BigEndian.Uint32(ts[:4])|1)
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

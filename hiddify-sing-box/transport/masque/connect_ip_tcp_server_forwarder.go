package masque

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

const connectIPTCPForwarderICMPRelayMax = 8

// ConnectIPTCPForwarderOptions carries generic MASQUE server policy knobs reused by the
// CONNECT-IP IPv4/TCP packet-plane forwarder (S2 path).
type ConnectIPTCPForwarderOptions struct {
	AllowPrivateTargets bool
	AllowedTargetPorts  []uint16
	BlockedTargetPorts  []uint16
	Dialer              net.Dialer
}

// RunConnectIPTCPPacketPlaneForwarder terminates IPv4 TCP inside CONNECT-IP into host TCP
// dials (S2). Non-IPv4-TCP packets are ignored (no router demux in this iteration).
//
// It blocks until ctx is done, conn read fails, or an unrecoverable write error occurs, then
// closes conn.
func RunConnectIPTCPPacketPlaneForwarder(ctx context.Context, conn *connectip.Conn, o ConnectIPTCPForwarderOptions) error {
	if conn == nil {
		return errors.New("masque: connect-ip forwarder: nil conn")
	}
	f := &connectIPTCPForwarder{
		conn: conn,
		o:    o,
	}
	if f.o.Dialer.Timeout == 0 && f.o.Dialer.Deadline.IsZero() {
		f.o.Dialer.Timeout = 8 * time.Second
	}
	defer func() {
		f.shutdownSessions()
		_ = conn.Close()
	}()
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		default:
		}
		n, err := conn.ReadPacket(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if n < header.IPv4MinimumSize {
			continue
		}
		pkt := buf[:n]
		if pkt[0]>>4 != 4 {
			continue
		}
		iph := header.IPv4(pkt)
		if !iph.IsValid(len(pkt)) || iph.Protocol() != uint8(header.TCPProtocolNumber) {
			continue
		}
		ihl := int(iph.HeaderLength())
		if ihl+header.TCPMinimumSize > len(pkt) {
			continue
		}
		tc := header.TCP(pkt[ihl:])
		doff := int(tc.DataOffset()) * 4
		if doff < header.TCPMinimumSize || ihl+doff > len(pkt) {
			continue
		}
		tcpLen := uint16(len(pkt) - ihl)
		payloadLen := tcpLen - uint16(doff)
		var payCsum uint16
		if payloadLen > 0 {
			payCsum = checksum.Checksum(pkt[ihl+doff:], 0)
		}
		if !tc.IsChecksumValid(iph.SourceAddress(), iph.DestinationAddress(), payCsum, payloadLen) {
			continue
		}
		flow := tcp4Tuple{
			srcAddr: iph.SourceAddress(),
			dstAddr: iph.DestinationAddress(),
			srcPort: tc.SourcePort(),
			dstPort: tc.DestinationPort(),
		}
		flags := tc.Flags()
		if flags&(header.TCPFlagSyn|header.TCPFlagAck) == header.TCPFlagSyn {
			f.handleSyn(ctx, pkt, iph, tc, flow)
			continue
		}
		if flags&header.TCPFlagRst != 0 {
			f.dropFlow(flow)
			continue
		}
		s := f.getSession(flow)
		if s == nil {
			continue
		}
		s.handleSegment(ctx, pkt, iph, tc, ihl, doff)
	}
}

type tcp4Tuple struct {
	srcAddr, dstAddr tcpip.Address
	srcPort, dstPort uint16
}

type connectIPTCPForwarder struct {
	conn *connectip.Conn
	o    ConnectIPTCPForwarderOptions
	wMu  sync.Mutex

	sMu    sync.Mutex
	synMu  sync.Mutex
	sessions map[tcp4Tuple]*tcpForwardSession
}

func (f *connectIPTCPForwarder) shutdownSessions() {
	f.sMu.Lock()
	for _, s := range f.sessions {
		if s != nil && s.remote != nil {
			_ = s.remote.Close()
		}
	}
	f.sessions = nil
	f.sMu.Unlock()
}

func (f *connectIPTCPForwarder) writeRaw(pkt []byte) error {
	f.wMu.Lock()
	defer f.wMu.Unlock()
	p := pkt
	for i := 0; i < connectIPTCPForwarderICMPRelayMax; i++ {
		icmp, err := f.conn.WritePacket(p)
		if err != nil {
			return err
		}
		if len(icmp) == 0 {
			return nil
		}
		p = icmp
	}
	return errors.New("masque: connect-ip forwarder: ICMP relay exceeded")
}

func (f *connectIPTCPForwarder) getSession(flow tcp4Tuple) *tcpForwardSession {
	f.sMu.Lock()
	defer f.sMu.Unlock()
	return f.sessions[flow]
}

func (f *connectIPTCPForwarder) dropFlow(flow tcp4Tuple) {
	f.sMu.Lock()
	s := f.sessions[flow]
	if s != nil {
		delete(f.sessions, flow)
	}
	f.sMu.Unlock()
	if s != nil && s.remote != nil {
		_ = s.remote.Close()
	}
}

func (f *connectIPTCPForwarder) addSession(flow tcp4Tuple, s *tcpForwardSession) {
	f.sMu.Lock()
	if f.sessions == nil {
		f.sessions = make(map[tcp4Tuple]*tcpForwardSession)
	}
	f.sessions[flow] = s
	f.sMu.Unlock()
}

func forwarderAllowDestIP(addr netip.Addr, allowPrivate bool) error {
	if !addr.IsValid() {
		return errors.New("invalid destination")
	}
	if allowPrivate {
		return nil
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
		return errors.New("private target denied")
	}
	return nil
}

func forwarderAllowPort(port uint16, allowList []uint16, denyList []uint16) bool {
	for _, d := range denyList {
		if d == port {
			return false
		}
	}
	if len(allowList) == 0 {
		return true
	}
	for _, a := range allowList {
		if a == port {
			return true
		}
	}
	return false
}

func (f *connectIPTCPForwarder) handleSyn(ctx context.Context, _ []byte, iph header.IPv4, tc header.TCP, flow tcp4Tuple) {
	f.synMu.Lock()
	defer f.synMu.Unlock()

	f.sMu.Lock()
	if f.sessions != nil {
		if existing := f.sessions[flow]; existing != nil {
			f.sMu.Unlock()
			existing.onRetransmittedSyn(tc)
			return
		}
	}
	f.sMu.Unlock()

	dstIP := netip.AddrFrom4(iph.DestinationAddress().As4())
	if err := forwarderAllowDestIP(dstIP, f.o.AllowPrivateTargets); err != nil {
		_ = f.sendRST(iph, tc, tc.SequenceNumber()+1)
		return
	}
	if !forwarderAllowPort(tc.DestinationPort(), f.o.AllowedTargetPorts, f.o.BlockedTargetPorts) {
		_ = f.sendRST(iph, tc, tc.SequenceNumber()+1)
		return
	}

	irs := tc.SequenceNumber()
	synOpts := header.ParseSynOptions(tc.Options(), false)
	mss := synOpts.MSS
	if mss == 0 || mss > 1460 {
		mss = 1460
	}

	dialAddr := net.JoinHostPort(dstIP.String(), strconv.Itoa(int(tc.DestinationPort())))
	remote, dialErr := f.o.Dialer.DialContext(ctx, "tcp", dialAddr)
	if dialErr != nil {
		_ = f.sendRST(iph, tc, irs+1)
		return
	}

	iss, err := randomISN()
	if err != nil {
		_ = remote.Close()
		_ = f.sendRST(iph, tc, irs+1)
		return
	}

	s := &tcpForwardSession{
		f:          f,
		flow:       flow,
		remote:     remote,
		irs:        irs,
		iss:        iss,
		rcvNxt:     irs + 1,
		sndNxt:     iss + 1,
		clientMSS:  mss,
		tsOK:       synOpts.TS,
		tsRecent:   synOpts.TSVal,
	}
	s.synAckOpts = buildSynAckTCPOptions(synOpts)

	s.add()
	if err := s.sendSynAck(iph, tc); err != nil {
		s.close()
		return
	}
}

func (f *connectIPTCPForwarder) sendRST(iph header.IPv4, tc header.TCP, ack uint32) error {
	srcIP := iph.DestinationAddress()
	dstIP := iph.SourceAddress()
	sport := tc.DestinationPort()
	dport := tc.SourcePort()
	return f.writeRaw(buildIPv4TCPPacket(srcIP, dstIP, sport, dport, 0, ack, header.TCPFlagRst|header.TCPFlagAck, 0, nil, nil))
}

type tcpForwardSession struct {
	f      *connectIPTCPForwarder
	flow   tcp4Tuple
	remote net.Conn

	mu sync.Mutex

	irs, iss   uint32
	rcvNxt     uint32
	sndNxt     uint32
	established bool

	clientMSS uint16

	tsOK       bool
	tsRecent   uint32

	synAckOpts []byte

	remoteReaderOnce sync.Once
	closed           atomic.Bool
}

func (s *tcpForwardSession) add() {
	s.f.addSession(s.flow, s)
}

func (s *tcpForwardSession) close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	_ = s.remote.Close()
	s.f.dropFlow(s.flow)
}

func (s *tcpForwardSession) onRetransmittedSyn(tc header.TCP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.established {
		return
	}
	if tc.SequenceNumber() != s.irs {
		return
	}
	pkt := buildIPv4TCPPacket(s.flow.dstAddr, s.flow.srcAddr, s.flow.dstPort, s.flow.srcPort,
		s.iss, s.irs+1, header.TCPFlagSyn|header.TCPFlagAck, 65535, nil, s.synAckOpts)
	_ = s.f.writeRaw(pkt)
}

func (s *tcpForwardSession) sendSynAck(iph header.IPv4, tc header.TCP) error {
	pkt := buildIPv4TCPPacket(
		iph.DestinationAddress(), iph.SourceAddress(),
		tc.DestinationPort(), tc.SourcePort(),
		s.iss, s.irs+1,
		header.TCPFlagSyn|header.TCPFlagAck,
		65535,
		nil,
		s.synAckOpts,
	)
	return s.f.writeRaw(pkt)
}

func (s *tcpForwardSession) handleSegment(ctx context.Context, pkt []byte, iph header.IPv4, tc header.TCP, ipHdrLen, tcpHdrLen int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	flags := tc.Flags()
	ack := tc.AckNumber()
	seq := tc.SequenceNumber()

	if s.tsOK {
		if po := tc.ParsedOptions(); po.TS {
			s.tsRecent = po.TSVal
		}
	}

	if !s.established {
		if flags&header.TCPFlagAck != 0 && ack == s.iss+1 && flags&header.TCPFlagSyn == 0 {
			s.established = true
			s.remoteReaderOnce.Do(func() { go s.pumpRemoteToClient(ctx) })
		}
	}

	payload := pkt[ipHdrLen+tcpHdrLen:]
	if len(payload) > 0 {
		if !s.established {
			return
		}
		if seq != s.rcvNxt {
			_ = s.sendAckOnly()
			return
		}
		if _, err := s.remote.Write(payload); err != nil {
			go s.close()
			return
		}
		s.rcvNxt += uint32(len(payload))
		_ = s.sendAckOnly()
	}

	if flags&header.TCPFlagFin != 0 {
		if !s.established {
			return
		}
		finSeq := seq + uint32(len(payload))
		if finSeq != s.rcvNxt {
			_ = s.sendAckOnly()
			return
		}
		s.rcvNxt++
		_ = s.sendAckOnly()
		if cw, ok := s.remote.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
}

func (s *tcpForwardSession) sendAckOnly() error {
	opts := s.buildTimestampOption()
	pkt := buildIPv4TCPPacket(
		s.flow.dstAddr, s.flow.srcAddr,
		s.flow.dstPort, s.flow.srcPort,
		s.sndNxt, s.rcvNxt,
		header.TCPFlagAck,
		65535,
		nil,
		opts,
	)
	return s.f.writeRaw(pkt)
}

func (s *tcpForwardSession) buildTimestampOption() []byte {
	if !s.tsOK {
		return nil
	}
	var b [12]byte
	b[0] = header.TCPOptionNOP
	b[1] = header.TCPOptionNOP
	b[2] = header.TCPOptionTS
	b[3] = header.TCPOptionTSLength
	ts := uint32(time.Now().UnixNano())
	binary.BigEndian.PutUint32(b[4:], ts)
	binary.BigEndian.PutUint32(b[8:], s.tsRecent)
	return b[:]
}

func (s *tcpForwardSession) pumpRemoteToClient(ctx context.Context) {
	defer s.close()
	buf := make([]byte, int(s.clientMSS))
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = s.remote.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := s.remote.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		off := 0
		for off < n {
			if err := ctx.Err(); err != nil {
				return
			}
			chunk := n - off
			maxData := int(s.clientMSS) - 80
			if chunk > maxData {
				chunk = maxData
			}
			payload := buf[off : off+chunk]
			s.mu.Lock()
			seq := s.sndNxt
			s.sndNxt += uint32(chunk)
			opts := s.buildTimestampOption()
			pkt := buildIPv4TCPPacket(
				s.flow.dstAddr, s.flow.srcAddr,
				s.flow.dstPort, s.flow.srcPort,
				seq, s.rcvNxt,
				header.TCPFlagPsh|header.TCPFlagAck,
				65535,
				payload,
				opts,
			)
			s.mu.Unlock()
			if err := s.f.writeRaw(pkt); err != nil {
				return
			}
			off += chunk
		}
	}
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
	pkt := make([]byte, totalLen)
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
	tc := header.TCP(pkt[tcpOff : tcpOff+tcpHdrLen])
	copy(tc[header.TCPMinimumSize:], tcpOpts)
	tf := header.TCPFields{
		SrcPort:       srcPort,
		DstPort:       dstPort,
		SeqNum:        seq,
		AckNum:        ack,
		DataOffset:    uint8(tcpHdrLen / 4),
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

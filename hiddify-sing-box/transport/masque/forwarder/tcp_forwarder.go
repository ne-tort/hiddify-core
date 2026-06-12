package forwarder

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

type tcp4Tuple struct {
	srcAddr, dstAddr tcpip.Address
	srcPort, dstPort uint16
}

type packetForwarder struct {
	conn PacketPlaneConn
	o    ConnectIPTCPForwarderOptions
	wMu  sync.Mutex
	writeCh      chan []byte
	writeStopped chan struct{}
	peerPrefixes atomic.Value // []netip.Prefix
	ackTSTick    atomic.Uint32

	sMu    sync.Mutex
	synMu  sync.Mutex
	sessions map[tcp4Tuple]*tcpForwardSession

	uMu         sync.Mutex
	udpSessions map[udp4Tuple]*udpForwardSession
}

// RunConnectIPTCPPacketPlaneForwarder terminates IPv4 TCP and UDP inside CONNECT-IP into host
// TCP/UDP dials (S2). Other protocols are ignored.
//
// It blocks until ctx is done, conn read fails, or an unrecoverable write error occurs, then
// closes conn.
func RunConnectIPTCPPacketPlaneForwarder(ctx context.Context, conn PacketPlaneConn, o ConnectIPTCPForwarderOptions) error {
	if conn == nil {
		return errors.New("masque: connect-ip forwarder: nil conn")
	}
	if strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1" {
		log.Printf("masque connect_ip forwarder: started")
	}
	f := &packetForwarder{
		conn:         conn,
		o:            o,
		writeCh:      make(chan []byte, writeQueueDepth),
		writeStopped: make(chan struct{}),
	}
	if f.o.Dialer.Timeout == 0 && f.o.Dialer.Deadline.IsZero() {
		f.o.Dialer.Timeout = 8 * time.Second
	}
	writeDone := make(chan struct{})
	go f.runWriteLoop(ctx, writeDone)
	defer func() {
		close(f.writeStopped)
		f.shutdownSessions()
		close(f.writeCh)
		<-writeDone
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
		if strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1" {
			log.Printf("masque connect_ip forwarder: read n=%d first_byte=0x%02x", n, buf[0])
		}
		pkt := buf[:n]
		if pkt[0]>>4 != 4 || len(pkt) < header.IPv4MinimumSize {
			continue
		}
		if pkt[9] == uint8(header.UDPProtocolNumber) {
			f.handleUDPPacket(ctx, pkt, header.IPv4(pkt))
			continue
		}
		if pkt[9] != uint8(header.TCPProtocolNumber) {
			continue
		}
		iph := header.IPv4(pkt)
		if totalLen := int(iph.TotalLength()); totalLen >= header.IPv4MinimumSize && totalLen < len(pkt) {
			pkt = pkt[:totalLen]
			iph = header.IPv4(pkt)
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < header.IPv4MinimumSize || ihl+header.TCPMinimumSize > len(pkt) {
			continue
		}
		tc := header.TCP(pkt[ihl:])
		doff := int(pkt[ihl+12]>>4) * 4
		if doff < header.TCPMinimumSize || ihl+doff > len(pkt) {
			if strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1" {
				log.Printf("masque connect_ip forwarder: drop invalid tcp header doff=%d ihl=%d len=%d", doff, ihl, len(pkt))
			}
			continue
		}
		tcpLen := uint16(len(pkt) - ihl)
		payloadLen := tcpLen - uint16(doff)
		var payCsum uint16
		if payloadLen > 0 {
			payCsum = checksum.Checksum(pkt[ihl+doff:], 0)
		}
		if csum := tc.Checksum(); csum != 0 && !tc.IsChecksumValid(iph.SourceAddress(), iph.DestinationAddress(), payCsum, payloadLen) {
			if strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1" {
				log.Printf("masque connect_ip forwarder: drop bad tcp checksum csum=0x%04x", csum)
			}
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
		if strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1" && flags&header.TCPFlagSyn != 0 {
			log.Printf("masque connect_ip forwarder: skip non-syn flags=0x%02x", flags)
		}
		if flags&header.TCPFlagRst != 0 {
			f.dropFlow(flow)
			continue
		}
		s := f.getSession(flow)
		if s == nil {
			if strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1" {
				log.Printf("masque connect_ip forwarder: no session flags=0x%x %s:%d -> %s:%d",
					uint8(flags), flow.srcAddr, flow.srcPort, flow.dstAddr, flow.dstPort)
			}
			continue
		}
		s.handleSegment(ctx, pkt, iph, tc, ihl, doff)
	}
}

func (f *packetForwarder) runWriteLoop(ctx context.Context, done chan struct{}) {
	defer close(done)
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-f.writeCh:
			if !ok {
				return
			}
			f.o.WriteQueueMetrics.noteDequeued()
			f.wMu.Lock()
			err := f.writeRawLocked(pkt)
			f.wMu.Unlock()
			returnPacket(pkt)
			if err != nil && strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1" {
				log.Printf("masque connect_ip forwarder: write loop err=%v", err)
			}
		}
	}
}

func (f *packetForwarder) enqueueWrite(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	if f.writeCh == nil {
		f.wMu.Lock()
		err := f.writeRawLocked(pkt)
		f.wMu.Unlock()
		returnPacket(pkt)
		return err
	}
	select {
	case <-f.writeStopped:
		returnPacket(pkt)
		return net.ErrClosed
	case f.writeCh <- pkt:
		f.o.WriteQueueMetrics.noteEnqueued()
		return nil
	default:
		select {
		case <-f.writeStopped:
			returnPacket(pkt)
			return net.ErrClosed
		case f.writeCh <- pkt:
			f.o.WriteQueueMetrics.noteEnqueued()
			return nil
		}
	}
}

func (f *packetForwarder) shutdownSessions() {
	f.sMu.Lock()
	for _, s := range f.sessions {
		if s != nil && s.remote != nil {
			_ = s.remote.Close()
		}
	}
	f.sessions = nil
	f.sMu.Unlock()
	f.uMu.Lock()
	for _, s := range f.udpSessions {
		if s != nil && s.remote != nil {
			_ = s.remote.Close()
		}
	}
	f.udpSessions = nil
	f.uMu.Unlock()
}

func (f *packetForwarder) writeRaw(pkt []byte) error {
	return f.enqueueWrite(pkt)
}

func (f *packetForwarder) peerPrefixesCached() []netip.Prefix {
	if v := f.peerPrefixes.Load(); v != nil {
		return v.([]netip.Prefix)
	}
	p := f.conn.CurrentPeerPrefixes()
	f.peerPrefixes.Store(p)
	return p
}

func (f *packetForwarder) writeRawLocked(pkt []byte) error {
	p := RewriteOutgoingPeerDst(pkt, f.peerPrefixesCached())
	for i := 0; i < icmpRelayMax; i++ {
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

func (f *packetForwarder) getSession(flow tcp4Tuple) *tcpForwardSession {
	f.sMu.Lock()
	defer f.sMu.Unlock()
	return f.sessions[flow]
}

func (f *packetForwarder) dropFlow(flow tcp4Tuple) {
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

func (f *packetForwarder) addSession(flow tcp4Tuple, s *tcpForwardSession) {
	f.sMu.Lock()
	if f.sessions == nil {
		f.sessions = make(map[tcp4Tuple]*tcpForwardSession)
	}
	f.sessions[flow] = s
	f.sMu.Unlock()
}

func (f *packetForwarder) handleSyn(ctx context.Context, _ []byte, iph header.IPv4, tc header.TCP, flow tcp4Tuple) {
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
	if err := allowDestIP(dstIP, f.o.AllowPrivateTargets); err != nil {
		_ = f.sendRST(iph, tc, tc.SequenceNumber()+1)
		return
	}
	if !allowPort(tc.DestinationPort(), f.o.AllowedTargetPorts, f.o.BlockedTargetPorts) {
		_ = f.sendRST(iph, tc, tc.SequenceNumber()+1)
		return
	}

	irs := tc.SequenceNumber()
	synOpts := header.ParseSynOptions(tc.Options(), false)
	mss := synOpts.MSS
	if mss == 0 || mss > 1460 {
		mss = 1460
	}

	dialAddr := DialAddr(dstIP, tc.DestinationPort())
	if strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1" {
		log.Printf("masque connect_ip forwarder: syn %s:%d -> dial %s", flow.srcAddr, flow.srcPort, dialAddr)
	}
	remote, dialErr := f.o.Dialer.DialContext(ctx, "tcp", dialAddr)
	if dialErr != nil {
		if strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1" {
			log.Printf("masque connect_ip forwarder: syn dial %s err=%v", dialAddr, dialErr)
		}
		_ = f.sendRST(iph, tc, irs+1)
		return
	}
	tuneRemote(remote)
	if strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1" {
		log.Printf("masque connect_ip forwarder: syn dial ok %s", dialAddr)
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
		outbound:   bufio.NewWriterSize(remote, remoteWriteBuf),
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
	if err := s.sendSynAck(ctx, iph, tc); err != nil {
		s.close()
		return
	}
}

func (f *packetForwarder) sendRST(iph header.IPv4, tc header.TCP, ack uint32) error {
	srcIP := iph.DestinationAddress()
	dstIP := iph.SourceAddress()
	sport := tc.DestinationPort()
	dport := tc.SourcePort()
	return f.writeRaw(buildIPv4TCPPacket(srcIP, dstIP, sport, dport, 0, ack, header.TCPFlagRst|header.TCPFlagAck, 0, nil, nil))
}

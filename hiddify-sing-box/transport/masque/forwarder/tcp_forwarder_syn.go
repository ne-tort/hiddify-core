package forwarder

import (
	"context"
	"log"

	"github.com/sagernet/gvisor/pkg/tcpip/header"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
)

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

func (f *packetForwarder) handleSyn(ctx context.Context, origPkt []byte, tc header.TCP, flow tcp4Tuple) {
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

	dstIP := netipFromTCPip(flow.dstAddr)
	if err := allowDestIP(dstIP, f.o.AllowPrivateTargets); err != nil {
		f.sendPolicyRejectICMP(origPkt)
		return
	}
	if !allowPort(tc.DestinationPort(), f.o.AllowedTargetPorts, f.o.BlockedTargetPorts) {
		f.sendPolicyRejectICMP(origPkt)
		return
	}

	irs := tc.SequenceNumber()
	synOpts := header.ParseSynOptions(tc.Options(), false)
	mss := synOpts.MSS
	if mss == 0 || mss > 1460 {
		mss = 1460
	}

	dialAddr := DialAddr(dstIP, tc.DestinationPort())
	if mcip.ConnectIPDebugEnabled() {
		log.Printf("masque connect_ip forwarder: syn %s:%d -> dial %s", flow.srcAddr, flow.srcPort, dialAddr)
	}

	iss, err := randomISN()
	if err != nil {
		_ = f.sendTCPRST(flow, irs+1)
		return
	}

	s := &tcpForwardSession{
		f:         f,
		flow:      flow,
		irs:       irs,
		iss:       iss,
		rcvNxt:    irs + 1,
		sndNxt:    iss + 1,
		clientMSS: mss,
		tsOK:      synOpts.TS,
		tsRecent:  synOpts.TSVal,
	}
	if synOpts.WS >= 0 {
		shift := synOpts.WS
		if shift > 14 {
			shift = 14
		}
		s.clientWSScale = byte(shift)
	}
	if synOpts.TS {
		s.tsSendNext = newForwarderSendTimestamp()
	}
	s.synAckOpts = buildSynAckTCPOptions(synOpts, s.tsSendNext)

	// Session + SYN-ACK before backend dial: client ACK must not arrive while session is absent.
	s.add()
	if err := s.sendSynAck(ctx); err != nil {
		s.close()
		return
	}

	remote, dialErr := f.o.Dialer.DialContext(ctx, "tcp", dialAddr)
	if dialErr != nil {
		if mcip.ConnectIPDebugEnabled() {
			log.Printf("masque connect_ip forwarder: syn dial %s err=%v", dialAddr, dialErr)
		}
		s.close()
		_ = f.sendTCPRST(flow, irs+1)
		return
	}
	tuneRemote(remote)
	if mcip.ConnectIPDebugEnabled() {
		log.Printf("masque connect_ip forwarder: syn dial ok %s", dialAddr)
	}

	s.bindRemote(remote)
	// S2C pump starts on first C2S payload (handleSegment), not on dial — iperf -R bulk before params races params.
	s.ensureHandshakeIdleWatchdog(ctx)
}

func (f *packetForwarder) sendTCPRST(flow tcp4Tuple, ack uint32) error {
	return f.writeRaw(buildIPTCPPacket(
		flow.dstAddr, flow.srcAddr,
		flow.dstPort, flow.srcPort,
		0, ack,
		header.TCPFlagRst|header.TCPFlagAck,
		0, nil, nil,
	))
}

func (f *packetForwarder) sendPolicyRejectICMP(origPkt []byte) {
	if len(origPkt) > 0 && origPkt[0]>>4 == 6 {
		_ = f.sendICMPv6AdminProhibited(origPkt)
		return
	}
	_ = f.sendICMPAdminProhibited(origPkt)
}

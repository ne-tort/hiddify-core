package forwarder

import (
	"context"

	"github.com/sagernet/gvisor/pkg/tcpip/header"
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
		s2cWake:   make(chan struct{}, 1),
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
	// P6-B1: do NOT Dial under the packet read loop / synMu — parallel SYNs (iperf -P≥4)
	// blocked ingress for the duration of each backend dial and starved sibling handshakes.
	s.add()
	if err := s.sendSynAck(ctx); err != nil {
		s.close()
		return
	}
	s.ensureHandshakeIdleWatchdog(ctx)

	go f.dialBackendForSession(ctx, s, dialAddr, irs)
}

// dialBackendForSession completes S2 host dial off the CONNECT-IP read path.
func (f *packetForwarder) dialBackendForSession(ctx context.Context, s *tcpForwardSession, dialAddr string, irs uint32) {
	remote, dialErr := f.o.Dialer.DialContext(ctx, "tcp", dialAddr)
	if dialErr != nil {
		s.close()
		_ = f.sendTCPRST(s.flow, irs+1)
		return
	}
	if s.closed.Load() {
		_ = remote.Close()
		return
	}
	tuneRemote(remote)
	s.bindRemote(remote)
	// S2C pump starts on first C2S payload (handleSegment), not on dial — iperf -R bulk before params races params.
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

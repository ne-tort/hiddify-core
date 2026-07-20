package forwarder

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/sing-box/transport/masque/connectip/relaystats"
)

type tcpForwardSession struct {
	f      *packetForwarder
	flow   tcp4Tuple
	remote net.Conn
	outbound *bufio.Writer

	mu sync.Mutex

	irs, iss   uint32
	rcvNxt     uint32
	sndNxt     uint32
	established bool
	synAckSent bool

	clientMSS uint16

	tsOK       bool
	tsRecent   uint32
	tsSendNext uint32 // monotonic server TS (SYN-ACK seed); PAWS on client requires TS to increase

	synAckOpts []byte

	pendingRemote [][]byte // C2S payload before backend dial completes (SYN-ACK before dial race)
	preClientS2C  []byte   // S2C from remote before client payload seen (do not discard)
	s2cWake         chan struct{}

	remoteReaderOnce sync.Once
	remoteFinSent    bool
	remotePumpDone   atomic.Bool
	clientPayloadSeen atomic.Bool
	s2cAllowWithoutClientPayload atomic.Bool // pure download / post-recycle probe before any C2S DATA
	closed           atomic.Bool
	handshakeIdleOnce sync.Once

	peerAck         uint32 // client ack (snd_una): bytes client received from forwarder
	peerRwnd        uint32 // scaled receive window advertised by client
	peerRwndValid   bool
	clientWSScale   uint8

	// P6-B2: S2 terminate synthesizes TCP over CONNECT-IP DATAGRAMs (H3 unreliable).
	// Retain unacked S2C payload for RTO retransmit — without this, one lost DATAGRAM stalls forever.
	s2cUnacked      []byte
	s2cUnackedSeq   uint32
	s2cLastProgress time.Time // last peerAck advance or successful RTO send
	s2cRTO          time.Duration
}

const (
	tcpForwarderHandshakeIdle     = 15 * time.Second
	tcpForwarderSyncAckMaxPayload = 512
	tcpForwarderS2CReto           = 200 * time.Millisecond
	tcpForwarderS2CRetoMax        = 2 * time.Second
)

// trimPayloadAtRcvNxt accepts overlapping TCP retransmissions (RFC 793): deliver bytes at rcvNxt only.
func trimPayloadAtRcvNxt(seq, rcvNxt uint32, payload []byte) ([]byte, bool) {
	if len(payload) == 0 {
		return payload, true
	}
	if seq < rcvNxt {
		end := seq + uint32(len(payload))
		if end <= rcvNxt {
			return nil, true // duplicate
		}
		drop := int(rcvNxt - seq)
		payload = payload[drop:]
	}
	if seq > rcvNxt {
		return nil, false // gap
	}
	return payload, true
}

func (s *tcpForwardSession) add() {
	s.f.addSession(s.flow, s)
}

func (s *tcpForwardSession) close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	if s.outbound != nil {
		_ = s.outbound.Flush()
	}
	if s.remote != nil {
		_ = s.remote.Close()
	}
	s.mu.Lock()
	for _, pay := range s.pendingRemote {
		returnPacket(pay)
	}
	s.pendingRemote = nil
	s.mu.Unlock()
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
	pkt := buildIPTCPPacket(s.flow.dstAddr, s.flow.srcAddr, s.flow.dstPort, s.flow.srcPort,
		s.iss, s.irs+1, header.TCPFlagSyn|header.TCPFlagAck, 65535, nil, s.synAckOpts)
	if err := s.f.writeRaw(pkt); err != nil {
		return
	}
	s.synAckSent = true
}

func (s *tcpForwardSession) sendSynAck(ctx context.Context) error {
	pkt := buildIPTCPPacket(
		s.flow.dstAddr, s.flow.srcAddr,
		s.flow.dstPort, s.flow.srcPort,
		s.iss, s.irs+1,
		header.TCPFlagSyn|header.TCPFlagAck,
		65535,
		nil,
		s.synAckOpts,
	)
	if err := s.f.writeRaw(pkt); err != nil {
		return err
	}
	s.mu.Lock()
	s.synAckSent = true
	s.mu.Unlock()
	return nil
}

func (s *tcpForwardSession) handleSegment(ctx context.Context, pkt []byte, tc header.TCP, ipHdrLen, tcpHdrLen int) {
	flags := tc.Flags()
	ack := tc.AckNumber()
	seq := tc.SequenceNumber()
	payload := pkt[ipHdrLen+tcpHdrLen:]

	s.mu.Lock()

	if s.tsOK {
		if po := tc.ParsedOptions(); po.TS {
			s.tsRecent = po.TSVal
		}
	}

	if flags&header.TCPFlagAck != 0 && ack >= s.iss+1 {
		if !s.established && flags&header.TCPFlagSyn == 0 {
			s.established = true
		}
		if s.established {
			s.notePeerSendWindowLocked(ack, tc.WindowSize())
		}
	}

	var (
		payCopy      []byte
		outbound     *bufio.Writer
		doSyncAck    bool
		doSchedAck   bool
		queuePending bool
		startPump    bool
		finClose     net.Conn
		dropEarly    bool
	)

	if len(payload) > 0 {
		if !s.established && !s.synAckSent {
			s.mu.Unlock()
			return
		}
		trimmed, ok := trimPayloadAtRcvNxt(seq, s.rcvNxt, payload)
		if !ok {
			doSchedAck = true
			dropEarly = true
		} else if len(trimmed) == 0 {
			doSchedAck = true
			dropEarly = true
		} else {
			payload = trimmed
			s.rcvNxt += uint32(len(payload))
			// Before remote flush: stop pump pretest discard so early iperf -R bytes are not dropped.
			s.clientPayloadSeen.Store(true)
			s.signalS2CPump()
			// usque order: ACK client before backend forward (iperf -R params stall).
			doSyncAck = len(payload) <= tcpForwarderSyncAckMaxPayload
			doSchedAck = !doSyncAck
			// Inline remote write prep: pkt is reused by the read loop after return.
			payCopy = borrowPacket(len(payload))
			copy(payCopy, payload)
			if s.closed.Load() {
				returnPacket(payCopy)
				payCopy = nil
				dropEarly = true
			} else if s.outbound == nil {
				s.pendingRemote = append(s.pendingRemote, payCopy)
				payCopy = nil
				queuePending = true
				startPump = true
			} else {
				outbound = s.outbound
				startPump = true
			}
		}
	}

	if !dropEarly && len(payload) == 0 && s.established && flags&header.TCPFlagAck != 0 {
		// Pure ACK after handshake: start S2C pump for download-only / iperf -R probes.
		s.s2cAllowWithoutClientPayload.Store(true)
		startPump = true
	}

	if flags&header.TCPFlagFin != 0 && s.established {
		wirePayloadLen := len(pkt[ipHdrLen+tcpHdrLen:])
		finSeq := seq + uint32(wirePayloadLen)
		if finSeq != s.rcvNxt {
			doSchedAck = true
		} else {
			s.rcvNxt++
			doSchedAck = true
			finClose = s.remote
		}
	}

	s.mu.Unlock()

	// P6-B2: never hold s.mu across sendPacketNow / host Write — async dial's bindRemote
	// must take s.mu promptly or C2S probes stay in pendingRemote forever under SYN storms.
	if doSyncAck {
		if err := s.sendAckNowSync(); err != nil {
			if payCopy != nil {
				returnPacket(payCopy)
			}
			go s.close()
			return
		}
	} else if doSchedAck {
		_ = s.scheduleAckOnly()
	}
	if queuePending {
		s.ensureRemotePump(ctx)
		return
	}
	if payCopy != nil && outbound != nil {
		if _, err := outbound.Write(payCopy); err != nil {
			returnPacket(payCopy)
			go s.close()
			return
		}
		returnPacket(payCopy)
		s.mu.Lock()
		flushErr := s.maybeFlushRemote(len(payload) <= 512)
		s.mu.Unlock()
		if flushErr != nil {
			go s.close()
			return
		}
		startPump = true
	}
	if startPump {
		s.ensureRemotePump(ctx)
	}
	if finClose != nil {
		if cw, ok := finClose.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
}

func (s *tcpForwardSession) bindRemote(remote net.Conn) {
	s.mu.Lock()
	s.remote = remote
	s.outbound = bufio.NewWriterSize(remote, remoteWriteBuf)
	s.mu.Unlock()
	s.signalS2CPump() // wake pump waiting for async dial (P6-B1)
	s.flushPendingRemote(true)
}

// flushPendingRemote delivers payload queued before backend dial completed.
func (s *tcpForwardSession) flushPendingRemote(immediate bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.outbound == nil || len(s.pendingRemote) == 0 {
		return
	}
	for _, pay := range s.pendingRemote {
		if s.closed.Load() {
			for _, p := range s.pendingRemote {
				returnPacket(p)
			}
			s.pendingRemote = nil
			return
		}
		if _, err := s.outbound.Write(pay); err != nil {
			for _, p := range s.pendingRemote {
				returnPacket(p)
			}
			s.pendingRemote = nil
			go s.close()
			return
		}
		returnPacket(pay)
	}
	s.pendingRemote = nil
	if err := s.maybeFlushRemote(immediate); err != nil {
		go s.close()
	}
}

func (s *tcpForwardSession) ensureRemotePump(ctx context.Context) {
	s.remoteReaderOnce.Do(func() { go s.pumpRemoteToClient(ctx) })
}

func (s *tcpForwardSession) sendFinOnRemoteClose() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.remoteFinSent || !s.established {
		return nil
	}
	s.remoteFinSent = true
	opts := s.buildTimestampOptionLocked()
	pkt := buildIPTCPPacket(
		s.flow.dstAddr, s.flow.srcAddr,
		s.flow.dstPort, s.flow.srcPort,
		s.sndNxt, s.rcvNxt,
		header.TCPFlagFin|header.TCPFlagAck,
		65535,
		nil,
		opts,
	)
	s.sndNxt++
	return s.f.enqueueWrite(pkt)
}

func (s *tcpForwardSession) buildAckOnlyPacket() []byte {
	opts := s.buildTimestampOptionLocked()
	return buildIPTCPPacket(
		s.flow.dstAddr, s.flow.srcAddr,
		s.flow.dstPort, s.flow.srcPort,
		s.sndNxt, s.rcvNxt,
		header.TCPFlagAck,
		65535,
		nil,
		opts,
	)
}

func (s *tcpForwardSession) scheduleAckOnly() error {
	// Coalesce via writeCh drain (coalesceQueuedAckOnly), not ackCh batch flush:
	// ackCh-only coalescing capped windowed upload at ~64 KiB/RTT in-proc.
	return s.sendAckOnly()
}

func (s *tcpForwardSession) sendAckOnly() error {
	pkt := s.buildAckOnlyPacket()
	if len(pkt) == 0 {
		return nil
	}
	return s.f.enqueueWrite(pkt)
}

// sendAckNowSync delivers ACK before short-payload remote write so downloadCh DATA cannot
// win the writeCh ACK queue (iperf -R: 89B params then 53B header).
func (s *tcpForwardSession) sendAckNowSync() error {
	pkt := s.buildAckOnlyPacket()
	if len(pkt) == 0 {
		return nil
	}
	err := s.f.sendPacketNow(pkt)
	returnPacket(pkt)
	return err
}

func (s *tcpForwardSession) maybeFlushRemote(immediate bool) error {
	if s.outbound == nil {
		return nil
	}
	if immediate || s.outbound.Buffered() >= remoteFlushBatch {
		return s.outbound.Flush()
	}
	return nil
}

// buildTimestampOptionLocked builds TS option; caller must hold s.mu.
func (s *tcpForwardSession) buildTimestampOptionLocked() []byte {
	if !s.tsOK {
		return nil
	}
	if s.tsSendNext == 0 {
		s.tsSendNext = newForwarderSendTimestamp()
	}
	s.tsSendNext++
	ts := s.tsSendNext
	recent := s.tsRecent
	var b [12]byte
	b[0] = header.TCPOptionNOP
	b[1] = header.TCPOptionNOP
	b[2] = header.TCPOptionTS
	b[3] = header.TCPOptionTSLength
	binary.BigEndian.PutUint32(b[4:], ts)
	binary.BigEndian.PutUint32(b[8:], recent)
	return b[:]
}

func (s *tcpForwardSession) maybeCloseAfterPump() {
	if s.remotePumpDone.Load() {
		s.close()
	}
}

func (s *tcpForwardSession) ensureHandshakeIdleWatchdog(ctx context.Context) {
	s.handshakeIdleOnce.Do(func() {
		go s.handshakeIdleWatchdog(ctx)
	})
}

func (s *tcpForwardSession) handshakeIdleWatchdog(ctx context.Context) {
	timer := time.NewTimer(tcpForwarderHandshakeIdle)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	s.mu.Lock()
	established := s.established
	s.mu.Unlock()
	if !established && !s.closed.Load() {
		s.close()
	}
}

func (s *tcpForwardSession) signalS2CPump() {
	if s == nil || s.s2cWake == nil {
		return
	}
	select {
	case s.s2cWake <- struct{}{}:
	default:
	}
}

// notePeerSendWindowLocked records client ACK/window for S2C pacing (host-kernel tun needs this).
func (s *tcpForwardSession) notePeerSendWindowLocked(ack uint32, win uint16) {
	woke := false
	if ack > s.peerAck {
		s.peerAck = ack
		s.trimS2CUnackedLocked(ack)
		s.s2cLastProgress = time.Now()
		s.s2cRTO = tcpForwarderS2CReto
		woke = true
	}
	wnd := uint32(win) << uint32(s.clientWSScale)
	if wnd == 0 {
		wnd = 1
	}
	if !s.peerRwndValid || wnd != s.peerRwnd {
		s.peerRwnd = wnd
		s.peerRwndValid = true
		woke = true
	}
	if woke {
		s.signalS2CPump()
	}
}

func (s *tcpForwardSession) trimS2CUnackedLocked(ack uint32) {
	if len(s.s2cUnacked) == 0 {
		return
	}
	if ack <= s.s2cUnackedSeq {
		return
	}
	delta := int(ack - s.s2cUnackedSeq)
	if delta >= len(s.s2cUnacked) {
		s.s2cUnacked = nil
		s.s2cUnackedSeq = ack
		return
	}
	s.s2cUnacked = s.s2cUnacked[delta:]
	s.s2cUnackedSeq = ack
}

func (s *tcpForwardSession) appendS2CUnackedLocked(seq uint32, payload []byte) {
	if len(payload) == 0 {
		return
	}
	if len(s.s2cUnacked) == 0 {
		s.s2cUnackedSeq = seq
		s.s2cLastProgress = time.Now()
		if s.s2cRTO == 0 {
			s.s2cRTO = tcpForwarderS2CReto
		}
	}
	s.s2cUnacked = append(s.s2cUnacked, payload...)
}

func (s *tcpForwardSession) s2cRTOIntervalLocked() time.Duration {
	if s.s2cRTO == 0 {
		return tcpForwarderS2CReto
	}
	return s.s2cRTO
}

func (s *tcpForwardSession) s2cRTODueLocked() bool {
	return len(s.s2cUnacked) > 0 && !s.s2cLastProgress.IsZero() &&
		time.Since(s.s2cLastProgress) >= s.s2cRTOIntervalLocked()
}

// retransmitS2CUnacked resends only the head MSS of unacked S2C (TCP-like RTO),
// not the whole window — full-window flood starved parallel SYN-ACKs on H3 DATAGRAM.
func (s *tcpForwardSession) retransmitS2CUnacked(maxSeg int) error {
	if s.closed.Load() || s.f.egressStopped() {
		return net.ErrClosed
	}
	s.mu.Lock()
	if len(s.s2cUnacked) == 0 {
		s.mu.Unlock()
		return nil
	}
	chunk := len(s.s2cUnacked)
	if chunk > maxSeg {
		chunk = maxSeg
	}
	payload := append([]byte(nil), s.s2cUnacked[:chunk]...)
	seq := s.s2cUnackedSeq
	rcvNxt := s.rcvNxt
	opts := s.buildTimestampOptionLocked()
	s.s2cLastProgress = time.Now()
	next := s.s2cRTOIntervalLocked() * 2
	if next > tcpForwarderS2CRetoMax {
		next = tcpForwarderS2CRetoMax
	}
	if next < tcpForwarderS2CReto {
		next = tcpForwarderS2CReto
	}
	s.s2cRTO = next
	s.mu.Unlock()

	pkt := buildIPTCPPacket(
		s.flow.dstAddr, s.flow.srcAddr,
		s.flow.dstPort, s.flow.srcPort,
		seq, rcvNxt,
		header.TCPFlagPsh|header.TCPFlagAck,
		65535,
		payload,
		opts,
	)
	relaystats.RecordS2CRTORetransmit()
	return s.f.enqueueDownload(pkt)
}

func (s *tcpForwardSession) s2cSendBudgetLocked() uint32 {
	if !s.peerRwndValid {
		return ^uint32(0)
	}
	inflight := s.sndNxt - s.peerAck
	if inflight >= s.peerRwnd {
		return 0
	}
	return s.peerRwnd - inflight
}

func (s *tcpForwardSession) pumpRemoteToClient(ctx context.Context) {
	defer func() {
		s.remotePumpDone.Store(true)
		s.maybeCloseAfterPump()
	}()
	if s.s2cWake == nil {
		s.s2cWake = make(chan struct{}, 1)
	}
	// P6-B1: backend dial is async after SYN-ACK; C2S may start the pump before bindRemote.
	for {
		s.mu.Lock()
		remote := s.remote
		s.mu.Unlock()
		if remote != nil {
			break
		}
		if s.closed.Load() || ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-s.s2cWake:
		case <-time.After(2 * time.Millisecond):
		}
	}
	readSz := remoteReadBuf
	if mss := int(s.clientMSS); mss > 0 {
		if readSz < 32*mss {
			readSz = 32 * mss
		}
		// Cap S2C burst so client ACKs can drain before kernel/gVisor recv window fills.
		if cap := 16 * mss; readSz > cap {
			readSz = cap
		}
	}
	buf := make([]byte, readSz)
	maxSeg := maxSegmentPayloadForFlow(s.clientMSS, s.flow)
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		var data []byte
		if len(s.preClientS2C) > 0 {
			data = s.preClientS2C
			s.preClientS2C = nil
		} else {
			s.mu.Lock()
			rtoDue := s.s2cRTODueLocked()
			remote := s.remote
			s.mu.Unlock()
			if rtoDue {
				if err := s.retransmitS2CUnacked(maxSeg); err != nil {
					return
				}
				continue
			}
			if remote == nil {
				if s.closed.Load() || ctx.Err() != nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-s.s2cWake:
				case <-time.After(2 * time.Millisecond):
				}
				continue
			}
			readWait := 30 * time.Second
			s.mu.Lock()
			if len(s.s2cUnacked) > 0 && !s.s2cLastProgress.IsZero() {
				left := s.s2cRTOIntervalLocked() - time.Since(s.s2cLastProgress)
				if left < time.Millisecond {
					left = time.Millisecond
				}
				readWait = left
			}
			s.mu.Unlock()
			_ = remote.SetReadDeadline(time.Now().Add(readWait))
			n, err := remote.Read(buf)
			if n > 0 {
				data = append([]byte(nil), buf[:n]...)
			}
			if err != nil {
				if len(data) == 0 {
					if errors.Is(err, io.EOF) {
						_ = s.sendFinOnRemoteClose()
						return
					}
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						if s.closed.Load() || ctx.Err() != nil {
							return
						}
						s.mu.Lock()
						rtoDue = s.s2cRTODueLocked()
						s.mu.Unlock()
						if rtoDue {
							if err := s.retransmitS2CUnacked(maxSeg); err != nil {
								return
							}
						}
						continue
					}
					go s.close()
					return
				}
			}
		}
		if len(data) == 0 {
			continue
		}
		if !s.clientPayloadSeen.Load() && !s.s2cAllowWithoutClientPayload.Load() {
			s.preClientS2C = append(s.preClientS2C, data...)
			select {
			case <-ctx.Done():
				return
			case <-s.s2cWake:
			default:
			}
			continue
		}
		off := 0
		for off < len(data) {
			if err := ctx.Err(); err != nil {
				return
			}
			s.mu.Lock()
			rtoDue := s.s2cRTODueLocked()
			s.mu.Unlock()
			if rtoDue {
				if err := s.retransmitS2CUnacked(maxSeg); err != nil {
					return
				}
				continue
			}
			chunk := len(data) - off
			if chunk > maxSeg {
				chunk = maxSeg
			}
			for {
				s.mu.Lock()
				budget := s.s2cSendBudgetLocked()
				rtoDue = s.s2cRTODueLocked()
				rtoWait := s.s2cRTOIntervalLocked()
				s.mu.Unlock()
				if rtoDue {
					if err := s.retransmitS2CUnacked(maxSeg); err != nil {
						return
					}
					continue
				}
				if budget > 0 {
					if uint32(chunk) > budget {
						chunk = int(budget)
					}
					break
				}
				select {
				case <-ctx.Done():
					return
				case <-s.s2cWake:
				case <-time.After(rtoWait):
					if err := s.retransmitS2CUnacked(maxSeg); err != nil {
						return
					}
				}
			}
			payload := data[off : off+chunk]
			s.mu.Lock()
			seq := s.sndNxt
			s.sndNxt += uint32(chunk)
			s.appendS2CUnackedLocked(seq, payload)
			rcvNxt := s.rcvNxt
			opts := s.buildTimestampOptionLocked()
			s.mu.Unlock()
			pkt := buildIPTCPPacket(
				s.flow.dstAddr, s.flow.srcAddr,
				s.flow.dstPort, s.flow.srcPort,
				seq, rcvNxt,
				header.TCPFlagPsh|header.TCPFlagAck,
				65535,
				payload,
				opts,
			)
			if err := s.f.enqueueDownload(pkt); err != nil {
				return
			}
			off += chunk
		}
	}
}

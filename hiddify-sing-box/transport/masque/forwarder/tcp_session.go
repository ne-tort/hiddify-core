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

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/sing-box/transport/masque/connectip/relaystats"
)

type tcpForwardSession struct {
	f      *packetForwarder
	flow   tcp4Tuple
	remote net.Conn
	outbound *bufio.Writer

	mu    sync.Mutex
	outMu sync.Mutex // serializes bufio outbound Write/Flush (async C2S writer)

	irs, iss   uint32
	rcvNxt     uint32
	rcvAck     uint32 // wire ACK cursor; lags rcvNxt when ACK-after-Flush / onward-peer (DIAG)
	sndNxt     uint32
	established bool
	synAckSent bool

	onwardAckBase   uint64    // TCP_INFO Bytes_acked at bindRemote
	onwardAckOnce   sync.Once // peer-ACK poller
	onwardAckSeq0   uint32    // rcvAck at bindRemote (irs+1)

	clientMSS uint16

	tsOK       bool
	tsRecent   uint32
	tsSendNext uint32 // monotonic server TS (SYN-ACK seed); PAWS on client requires TS to increase

	synAckOpts []byte

	pendingRemote [][]byte // C2S payload before backend dial completes (SYN-ACK before dial race)
	preClientS2C  []byte   // S2C from remote before client payload seen (do not discard)
	s2cWake       chan struct{}
	c2sCh         chan []byte // async C2S → onward (avoids demux HOL on RTT Write/Flush)
	c2sWriterOnce sync.Once
	c2sCloseOnce  sync.Once

	remoteReaderOnce             sync.Once
	remoteFinSent                bool
	remotePumpDone               atomic.Bool
	clientPayloadSeen            atomic.Bool
	s2cAllowWithoutClientPayload atomic.Bool // pure download / post-recycle probe before any C2S DATA
	closed                       atomic.Bool
	handshakeIdleOnce            sync.Once
	outboundIdleFlush            *time.Timer // flushes residual < remoteFlushBatch (iperf results)
	// Bulk C2S ACK: byte/idle → writeCh; demux never Flushes (HOL → Recv-Q + nested SRTT↑).
	// Every-seg writeCh A/B colo: UP~84 SRTT~111 REJECT vs 8KiB coalesce ~100/SRTT~50.
	ackCoalesceTimer *time.Timer
	ackCoalesceArmed bool
	ackUnackedBytes  int
	ackBornNs        int64 // first accept in current ACK window (DIAG)

	peerAck       uint32 // client ack (snd_una): bytes client received from forwarder
	peerRwnd      uint32 // scaled receive window advertised by client
	peerRwndValid bool
	clientWSScale uint8
	serverWSScale uint8 // scale announced in SYN-ACK (independent of client offer)

	// P6-B2: S2 terminate synthesizes TCP over CONNECT-IP DATAGRAMs (H3 unreliable).
	// Retain unacked S2C payload for RTO retransmit — without this, one lost DATAGRAM stalls forever.
	s2cUnacked      []byte
	s2cUnackedSeq   uint32
	s2cLastProgress time.Time // last peerAck advance or successful RTO send
	s2cLastEnqueue  time.Time // last S2C DATA enqueue (interactive vs bulk path)
	s2cRTO          time.Duration

	// P6-C2: reusable ACK wire image — patch seq/ack/TS/checksum instead of full encode.
	ackWire []byte
	ackMeta ackWireMeta
}

// ackWireMeta holds byte offsets into ackWire for hot-patch fields.
type ackWireMeta struct {
	tcpOff    int
	tcpLen    int
	seqOff    int
	ackOff    int
	wndOff    int // TCP Window field
	tsValOff  int // -1 when no TS
	tsEchoOff int
	ipv4IDOff int // -1 for IPv6
	srcAddr   tcpip.Address
	dstAddr   tcpip.Address
	isIPv4    bool
}

const (
	tcpForwarderHandshakeIdle     = 15 * time.Second
	tcpForwarderSyncAckMaxPayload = 512
	tcpForwarderS2CReto           = 200 * time.Millisecond
	tcpForwarderS2CRetoMax        = 2 * time.Second
	// Bulk nested ACK via writeCh (never Flush under demux).
	// every-seg (+ clock batch) → UP~66 REJECT (2026-07-24); 2KiB flat;
	// 8KiB+50µs KEEP (~100) with ackClockBatchMax=8.
	ackCoalesceBytes = 8 << 10
	ackCoalesceIdle  = 50 * time.Microsecond
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
	s.c2sCloseOnce.Do(func() {
		if s.c2sCh != nil {
			close(s.c2sCh)
		}
	})
	s.outMu.Lock()
	if s.outboundIdleFlush != nil {
		_ = s.outboundIdleFlush.Stop()
		s.outboundIdleFlush = nil
	}
	if s.outbound != nil {
		_ = s.outbound.Flush()
	}
	s.outMu.Unlock()
	if s.remote != nil {
		_ = s.remote.Close()
	}
	s.mu.Lock()
	s.clearAckCoalesceLocked()
	s.ackUnackedBytes = 0
	for _, pay := range s.pendingRemote {
		returnPacket(pay)
	}
	s.pendingRemote = nil
	s.mu.Unlock()
	s.signalS2CPump() // wake pump waiting on remote/dial without 2ms poll
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
	wnd := s.advertisedWindowFieldLocked()
	pkt := buildIPTCPPacket(s.flow.dstAddr, s.flow.srcAddr, s.flow.dstPort, s.flow.srcPort,
		s.iss, s.irs+1, header.TCPFlagSyn|header.TCPFlagAck, wnd, nil, s.synAckOpts)
	if err := s.f.writeRaw(pkt); err != nil {
		return
	}
	s.synAckSent = true
}

func (s *tcpForwardSession) sendSynAck(ctx context.Context) error {
	wnd := s.advertisedWindowFieldLocked()
	pkt := buildIPTCPPacket(
		s.flow.dstAddr, s.flow.srcAddr,
		s.flow.dstPort, s.flow.srcPort,
		s.iss, s.irs+1,
		header.TCPFlagSyn|header.TCPFlagAck,
		wnd,
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
		doSyncAck    bool
		doSchedAck   bool
		queuePending bool
		enqueueC2S   bool
		startPump    bool
		finClose     net.Conn
		dropEarly    bool
		silenceAck   bool // full C2S queue: no dup-ACK (avoids fast-retransmit collapse)
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
			// pkt reused after return — copy for pendingRemote / async C2S queue.
			if s.closed.Load() {
				doSchedAck = true
				dropEarly = true
			} else if s.outbound == nil {
				if len(s.pendingRemote) >= c2sQueueDepth() {
					// Backpressure before dial: silence (no dup-ACK storm).
					silenceAck = true
					dropEarly = true
					relaystats.RecordC2SSilence()
				} else {
					payCopy = borrowPacket(len(payload))
					copy(payCopy, payload)
					s.pendingRemote = append(s.pendingRemote, payCopy)
					payCopy = nil
					s.rcvNxt += uint32(len(payload))
					s.clientPayloadSeen.Store(true)
					s.signalS2CPump()
					if !ackWireLagEnabled() {
						s.noteBulkAckLocked(len(payload), &doSyncAck, &doSchedAck)
					}
					queuePending = true
					startPump = true
				}
			} else if s.c2sCh != nil && len(s.c2sCh) >= cap(s.c2sCh) {
				// Queue full: demux must not block; silence — no rcvNxt, no dup-ACK
				// (dup-ACK → fast retransmit → cwnd/2 → colo ~70 Mbit ceiling).
				silenceAck = true
				dropEarly = true
				relaystats.RecordC2SSilence()
				relaystats.NoteC2SQueueHigh(uint64(len(s.c2sCh)))
			} else {
				// Enqueue after unlock; advance rcvNxt + ACK only on success.
				enqueueC2S = true
				startPump = true
			}
		}
	}

	if !dropEarly && len(payload) == 0 && s.established && flags&header.TCPFlagAck != 0 {
		// Pure ACK after handshake: start S2C pump for download-only / iperf -R probes.
		s.s2cAllowWithoutClientPayload.Store(true)
		s.signalS2CPump()
		startPump = true
	}

	if flags&header.TCPFlagFin != 0 && s.established {
		wirePayloadLen := len(pkt[ipHdrLen+tcpHdrLen:])
		finSeq := seq + uint32(wirePayloadLen)
		if finSeq != s.rcvNxt {
			doSchedAck = true
		} else {
			s.rcvNxt++
			if ackWireLagEnabled() {
				s.rcvAck = s.rcvNxt
			}
			// ACK-of-FIN must not sit on writeCh best-effort — pure ACK loss → client LAST-ACK.
			doSyncAck = true
			finClose = s.remote
		}
	}

	s.mu.Unlock()

	// P6-B2: never hold s.mu across sendPacketNow / host Write — async dial's bindRemote
	// must take s.mu promptly or C2S probes stay in pendingRemote forever under SYN storms.
	if !silenceAck {
		if doSyncAck {
			if err := s.sendAckNowSync(); err != nil {
				if payCopy != nil {
					returnPacket(payCopy)
				}
				go s.close()
				return
			}
		} else if doSchedAck {
			_ = s.sendAckOnly()
		}
	}
	if queuePending {
		s.ensureRemotePump(ctx)
		return
	}
	if enqueueC2S && len(payload) > 0 && !dropEarly {
		// Copy then async Write/Flush — never block demux on onward TCP RTT.
		// ACK only after accept so client never sees a rolled-back rcvNxt.
		s.ensureC2SWriter()
		payCopy = borrowPacket(len(payload))
		copy(payCopy, payload)
		if !s.enqueueC2S(payCopy) {
			returnPacket(payCopy)
			// Race-full: silence (same as len>=cap path) — no false loss signal.
			relaystats.RecordC2SSilence()
			return
		}
		payCopy = nil
		s.mu.Lock()
		s.rcvNxt += uint32(len(payload))
		s.clientPayloadSeen.Store(true)
		s.signalS2CPump()
		var ackSync, ackSched bool
		if !ackWireLagEnabled() {
			s.noteBulkAckLocked(len(payload), &ackSync, &ackSched)
		}
		s.mu.Unlock()
		if ackSync {
			if err := s.sendAckNowSync(); err != nil {
				go s.close()
				return
			}
		} else if ackSched {
			_ = s.sendAckOnly()
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
	if ackOnwardPeerEnabled() {
		s.onwardAckBase = onwardPeerBytesAcked(remote)
		s.onwardAckSeq0 = s.rcvAck
	}
	s.mu.Unlock()
	s.ensureC2SWriter()
	s.ensureOnwardPeerAckPoller()
	s.signalS2CPump() // wake pump waiting for async dial (P6-B1)
	s.flushPendingRemote(true)
}

// ensureC2SWriter starts the async onward writer (P6-SC: demux must not HOL on RTT).
func (s *tcpForwardSession) ensureC2SWriter() {
	s.c2sWriterOnce.Do(func() {
		s.c2sCh = make(chan []byte, c2sQueueDepth())
		go s.pumpClientToRemote()
	})
}

func (s *tcpForwardSession) enqueueC2S(pay []byte) (ok bool) {
	if s.closed.Load() || s.c2sCh == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	select {
	case s.c2sCh <- pay:
		relaystats.NoteC2SQueueHigh(uint64(len(s.c2sCh)))
		return true
	default:
		// Full: caller must not HOL demux; silence (no ACK), never advance rcvNxt.
		return false
	}
}

// noteBulkAckLocked chooses sync vs coalesced ACK for an accepted C2S payload.
// Small: sync. Bulk: never Flush under demux — byte/idle → writeCh (egress Flush).
// With ackClockBatchMax≥2, every-seg schedule is viable (Flush amortized).
func (s *tcpForwardSession) noteBulkAckLocked(payloadLen int, doSyncAck, doSchedAck *bool) {
	if payloadLen <= tcpForwarderSyncAckMaxPayload {
		s.markAckBornLocked()
		s.clearAckCoalesceLocked()
		s.ackUnackedBytes = 0
		*doSyncAck = true
		return
	}
	s.ackUnackedBytes += payloadLen
	if s.ackUnackedBytes >= ackCoalesceBytes {
		s.markAckBornLocked()
		s.ackUnackedBytes = 0
		s.clearAckCoalesceLocked()
		*doSchedAck = true
		return
	}
	s.armAckCoalesceLocked()
}

func (s *tcpForwardSession) markAckBornLocked() {
	if s.ackBornNs == 0 {
		s.ackBornNs = time.Now().UnixNano()
	}
}

func (s *tcpForwardSession) takeAckBornNs() int64 {
	s.mu.Lock()
	born := s.ackBornNs
	s.ackBornNs = 0
	s.mu.Unlock()
	return born
}

func (s *tcpForwardSession) emitAckAcceptToEnq() {
	born := s.takeAckBornNs()
	if born == 0 {
		return
	}
	relaystats.RecordAckAcceptToEnq(time.Duration(time.Now().UnixNano() - born))
}

func (s *tcpForwardSession) clearAckCoalesceLocked() {
	if s.ackCoalesceTimer != nil {
		_ = s.ackCoalesceTimer.Stop()
		s.ackCoalesceTimer = nil
	}
	s.ackCoalesceArmed = false
}

func (s *tcpForwardSession) armAckCoalesceLocked() {
	if s.ackCoalesceArmed {
		return
	}
	s.markAckBornLocked()
	s.ackCoalesceArmed = true
	s.ackCoalesceTimer = time.AfterFunc(ackCoalesceIdle, s.flushCoalescedAck)
}

func (s *tcpForwardSession) flushCoalescedAck() {
	s.mu.Lock()
	s.ackCoalesceArmed = false
	s.ackCoalesceTimer = nil
	s.ackUnackedBytes = 0
	closed := s.closed.Load()
	s.mu.Unlock()
	if closed {
		return
	}
	_ = s.sendAckOnly()
}

// advertisedWindowFieldLocked returns the TCP Window field (pre-scale).
// Tip KEEP: 65535 (× server WS≈10 → ~64MiB). Static caps REJECT (Mbps flat/↓).
// DIAG dynamic: free C2S absorb in bytes → field (never zero — H3 ZW sticky).
func (s *tcpForwardSession) advertisedWindowFieldLocked() uint16 {
	if !dynamicRwndEnabled() {
		return 65535
	}
	mss := int(s.clientMSS)
	if mss <= 0 {
		mss = 1460
	}
	freeSegs := 0
	if s.c2sCh != nil {
		freeSegs = cap(s.c2sCh) - len(s.c2sCh)
	} else {
		freeSegs = c2sQueueDepth() - len(s.pendingRemote)
	}
	if freeSegs < 1 {
		freeSegs = 1 // never advertise zero
	}
	freeBytes := uint32(freeSegs * mss)
	shift := uint32(s.serverWSScale)
	if shift > 14 {
		shift = 14
	}
	field := freeBytes >> shift
	if field > 65535 {
		field = 65535
	}
	if field < 1 {
		field = 1
	}
	return uint16(field)
}

// wireAckNumberLocked is the TCP ACK number on the wire.
// Tip: == rcvNxt. DIAG lag modes: rcvAck (Flush and/or onward peer Bytes_acked).
func (s *tcpForwardSession) wireAckNumberLocked() uint32 {
	if ackWireLagEnabled() {
		return s.rcvAck
	}
	return s.rcvNxt
}

// ackFlushCreditFullLocked reports write-credit exhausted (silence new C2S).
func (s *tcpForwardSession) ackFlushCreditFullLocked(add int) bool {
	if !ackAfterFlushEnabled() || add <= 0 {
		return false
	}
	unacked := s.rcvNxt - s.rcvAck
	return unacked+uint32(add) > ackFlushCreditBytes()
}

// onC2SFlushed advances wire ACK after onward Flush (ACK-after-Flush DIAG only).
func (s *tcpForwardSession) onC2SFlushed(n int) {
	if n <= 0 || !ackAfterFlushEnabled() || s.closed.Load() {
		return
	}
	s.mu.Lock()
	s.rcvAck += uint32(n)
	// Clamp: never ACK past accept cursor.
	if int32(s.rcvAck-s.rcvNxt) > 0 {
		s.rcvAck = s.rcvNxt
	}
	var ackSync, ackSched bool
	s.noteBulkAckLocked(n, &ackSync, &ackSched)
	s.mu.Unlock()
	if ackSync {
		if err := s.sendAckNowSync(); err != nil {
			go s.close()
		}
	} else if ackSched {
		_ = s.sendAckOnly()
	}
}

// ensureOnwardPeerAckPoller starts DIAG poller: nested wire ACK tracks onward peer ACK.
func (s *tcpForwardSession) ensureOnwardPeerAckPoller() {
	if !ackOnwardPeerEnabled() || s.closed.Load() {
		return
	}
	s.onwardAckOnce.Do(func() {
		go s.pollOnwardPeerAck()
	})
}

func (s *tcpForwardSession) pollOnwardPeerAck() {
	// 1ms: finer than onward RTT (~tens ms); cheap vs nested ACK rate.
	t := time.NewTicker(time.Millisecond)
	defer t.Stop()
	for !s.closed.Load() {
		<-t.C
		s.advanceAckFromOnwardPeer()
	}
}

func (s *tcpForwardSession) advanceAckFromOnwardPeer() {
	if !ackOnwardPeerEnabled() || s.closed.Load() {
		return
	}
	s.mu.Lock()
	remote := s.remote
	base := s.onwardAckBase
	seq0 := s.onwardAckSeq0
	s.mu.Unlock()
	if remote == nil {
		return
	}
	acked := onwardPeerBytesAcked(remote)
	if acked < base {
		return
	}
	delta := acked - base
	if delta > uint64(^uint32(0)) {
		delta = uint64(^uint32(0))
	}
	target := seq0 + uint32(delta)

	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		return
	}
	// Never ACK past accept cursor.
	if int32(target-s.rcvNxt) > 0 {
		target = s.rcvNxt
	}
	if target == s.rcvAck || int32(target-s.rcvAck) <= 0 {
		s.mu.Unlock()
		return
	}
	advanced := target - s.rcvAck
	s.rcvAck = target
	var ackSync, ackSched bool
	s.noteBulkAckLocked(int(advanced), &ackSync, &ackSched)
	s.mu.Unlock()
	if ackSync {
		if err := s.sendAckNowSync(); err != nil {
			go s.close()
		}
	} else if ackSched {
		_ = s.sendAckOnly()
	}
}

// pumpClientToRemote drains C2S payloads to the backend TCP (off demux).
// Coalesce already-queued segments into one Write/Flush up to remoteFlushBatch
// so onward TCP sees steady bursts (async pump — not demux HOL).
func (s *tcpForwardSession) pumpClientToRemote() {
	for pay := range s.c2sCh {
		if s.closed.Load() {
			returnPacket(pay)
			continue
		}
		s.mu.Lock()
		out := s.outbound
		s.mu.Unlock()
		if out == nil {
			s.mu.Lock()
			if s.outbound == nil {
				s.pendingRemote = append(s.pendingRemote, pay)
				s.mu.Unlock()
				continue
			}
			out = s.outbound
			s.mu.Unlock()
		}
		s.outMu.Lock()
		err := s.writeC2SBatchLocked(out, pay)
		s.outMu.Unlock()
		if err != nil {
			go s.close()
			return
		}
		// Dynamic rwnd: reopen advertised window as absorb frees (else client sticks).
		s.maybeSendWindowUpdate()
	}
}

// maybeSendWindowUpdate pushes an ACK-only so client sees reopened rcv window.
func (s *tcpForwardSession) maybeSendWindowUpdate() {
	if !dynamicRwndEnabled() || s.closed.Load() {
		return
	}
	_ = s.sendAckOnly()
}

// writeC2SBatchLocked writes pay plus any immediately available c2sCh payloads,
// flushing when buffered ≥ remoteFlushBatch or the channel is empty.
// On empty: always Flush (not idle-1ms) so onward TCP sees data without an extra
// timer delay under fat RTT. Caller holds outMu. pay is always returned to the pool.
func (s *tcpForwardSession) writeC2SBatchLocked(out *bufio.Writer, pay []byte) error {
	defer returnPacket(pay)
	if _, err := out.Write(pay); err != nil {
		return err
	}
	batched := len(pay)
	for batched < remoteFlushBatch {
		select {
		case more, ok := <-s.c2sCh:
			if !ok {
				if err := s.maybeFlushRemoteLocked(true); err != nil {
					return err
				}
				s.onC2SFlushed(batched)
				return nil
			}
			n := len(more)
			_, err := out.Write(more)
			returnPacket(more)
			if err != nil {
				return err
			}
			batched += n
		default:
			// Drain done: push to onward now (skip idle-1ms wait on bulk path).
			if err := s.maybeFlushRemoteLocked(true); err != nil {
				return err
			}
			s.onC2SFlushed(batched)
			return nil
		}
	}
	if err := s.maybeFlushRemoteLocked(true); err != nil {
		return err
	}
	s.onC2SFlushed(batched)
	return nil
}

// flushPendingRemote delivers payload queued before backend dial completed.
func (s *tcpForwardSession) flushPendingRemote(immediate bool) {
	s.ensureC2SWriter()
	s.mu.Lock()
	pending := s.pendingRemote
	s.pendingRemote = nil
	s.mu.Unlock()
	for _, pay := range pending {
		if s.closed.Load() {
			returnPacket(pay)
			continue
		}
		if !s.enqueueC2S(pay) {
			returnPacket(pay)
			go s.close()
			return
		}
	}
	_ = immediate // writer flushes via maybeFlushRemote / idle timer
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
		s.sndNxt, s.wireAckNumberLocked(),
		header.TCPFlagFin|header.TCPFlagAck,
		s.advertisedWindowFieldLocked(),
		nil,
		opts,
	)
	s.sndNxt++
	// FIN on downloadCh (not writeCh): writeCh priority would let FIN overtake
	// queued S2C DATA → client RST / iperf -P≥3 control death.
	return s.f.enqueueDownload(pkt)
}

func (s *tcpForwardSession) buildAckOnlyPacket() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buildAckOnlyPacketLocked()
}

// initAckWireLocked builds the session ACK template (caller holds s.mu).
func (s *tcpForwardSession) initAckWireLocked() {
	if len(s.ackWire) > 0 {
		return
	}
	var opts []byte
	if s.tsOK {
		if s.tsSendNext == 0 {
			s.tsSendNext = newForwarderSendTimestamp()
		}
		opts = []byte{
			header.TCPOptionNOP, header.TCPOptionNOP,
			header.TCPOptionTS, header.TCPOptionTSLength,
			0, 0, 0, 0, 0, 0, 0, 0,
		}
	}
	pkt := buildIPTCPPacket(
		s.flow.dstAddr, s.flow.srcAddr,
		s.flow.dstPort, s.flow.srcPort,
		s.sndNxt, 0,
		header.TCPFlagAck, 65535, nil, opts,
	)
	if len(pkt) == 0 {
		return
	}
	meta := parseAckWireMeta(pkt)
	if meta.tcpOff == 0 {
		returnPacket(pkt)
		return
	}
	s.ackMeta = meta
	s.ackWire = make([]byte, len(pkt))
	copy(s.ackWire, pkt)
	returnPacket(pkt)
}

func (s *tcpForwardSession) buildAckOnlyPacketLocked() []byte {
	wnd := s.advertisedWindowFieldLocked()
	if len(s.ackWire) == 0 {
		s.initAckWireLocked()
	}
	if len(s.ackWire) == 0 {
		// Fallback (malformed template): full encode.
		opts := s.buildTimestampOptionLocked()
		return buildIPTCPPacket(
			s.flow.dstAddr, s.flow.srcAddr,
			s.flow.dstPort, s.flow.srcPort,
			s.sndNxt, s.wireAckNumberLocked(),
			header.TCPFlagAck, wnd, nil, opts,
		)
	}
	pkt := borrowPacket(len(s.ackWire))
	copy(pkt, s.ackWire)
	m := s.ackMeta
	binary.BigEndian.PutUint32(pkt[m.seqOff:], s.sndNxt)
	binary.BigEndian.PutUint32(pkt[m.ackOff:], s.wireAckNumberLocked())
	if m.wndOff > 0 {
		binary.BigEndian.PutUint16(pkt[m.wndOff:], wnd)
	}
	if m.tsValOff >= 0 {
		s.tsSendNext++
		binary.BigEndian.PutUint32(pkt[m.tsValOff:], s.tsSendNext)
		binary.BigEndian.PutUint32(pkt[m.tsEchoOff:], s.tsRecent)
	}
	patchAckWireChecksums(pkt, m)
	return pkt
}

func (s *tcpForwardSession) sendAckOnly() error {
	// Coalesce via writeCh drain (coalesceQueuedAckOnly), not ackCh batch flush:
	// ackCh-only coalescing capped windowed upload at ~64 KiB/RTT in-proc.
	s.emitAckAcceptToEnq()
	pkt := s.buildAckOnlyPacket()
	if len(pkt) == 0 {
		return nil
	}
	return s.f.enqueueWrite(pkt)
}

// sendAckNowSync delivers ACK before short-payload remote write so downloadCh DATA cannot
// win the writeCh ACK queue (iperf -R: 89B params then 53B header).
// TryLock: if egress holds sendMu (H2 Flush / NoWake batch), enqueue writeCh instead of
// parking the single ReadPacket demux — that HOL-blocks bulk C2S window ACKs and stalls
// hot MultiShort (after_short==warm).
func (s *tcpForwardSession) sendAckNowSync() error {
	s.emitAckAcceptToEnq()
	pkt := s.buildAckOnlyPacket()
	if len(pkt) == 0 {
		return nil
	}
	if s.f.sendMu.TryLock() {
		var err error
		if cw, ok := s.f.conn.(packetPlaneCoalescedWriter); ok {
			err = s.f.writePacketRelayLocked(cw.WritePacketNoWake, pkt)
			if err == nil {
				// Flush outside sendMu (same as egress) — demux must not park on http2 Flush.
				s.f.flushDatagramOutsideSendMu(cw)
				s.f.noteAckFlushGap()
			}
		} else {
			err = s.f.writePacketRelayLocked(s.f.conn.WritePacket, pkt)
		}
		s.f.sendMu.Unlock()
		returnPacket(pkt)
		return err
	}
	return s.f.enqueueWrite(pkt)
}

func (s *tcpForwardSession) maybeFlushRemote(immediate bool) error {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	return s.maybeFlushRemoteLocked(immediate)
}

func (s *tcpForwardSession) maybeFlushRemoteLocked(immediate bool) error {
	if s.outbound == nil {
		return nil
	}
	if immediate || s.outbound.Buffered() >= remoteFlushBatch {
		if s.outboundIdleFlush != nil {
			_ = s.outboundIdleFlush.Stop()
		}
		t0 := time.Now()
		err := s.outbound.Flush()
		relaystats.RecordOnwardFlushDuration(time.Since(t0))
		return err
	}
	return nil
}

// armOutboundIdleFlushLocked flushes residual C2S below remoteFlushBatch after a
// short quiet (iperf control JSON). Caller holds outMu.
func (s *tcpForwardSession) armOutboundIdleFlushLocked() {
	if s.outbound == nil || s.outbound.Buffered() == 0 || s.closed.Load() {
		return
	}
	if s.outboundIdleFlush == nil {
		s.outboundIdleFlush = time.AfterFunc(remoteIdleFlushAfter, s.idleFlushOutbound)
		return
	}
	s.outboundIdleFlush.Reset(remoteIdleFlushAfter)
}

func (s *tcpForwardSession) idleFlushOutbound() {
	if s.closed.Load() {
		return
	}
	s.outMu.Lock()
	defer s.outMu.Unlock()
	if s.closed.Load() || s.outbound == nil || s.outbound.Buffered() == 0 {
		return
	}
	_ = s.outbound.Flush()
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

func (s *tcpForwardSession) ensureS2CWake() {
	if s.s2cWake == nil {
		s.s2cWake = make(chan struct{}, 1)
	}
}

func (s *tcpForwardSession) signalS2CPump() {
	if s == nil {
		return
	}
	s.ensureS2CWake()
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
	// buildIPTCPPacket copies payload into a borrowed wire pkt — no escape of s2cUnacked
	// across Unlock (trimS2CUnackedLocked may shrink the slice concurrently after unlock).
	payload := s.s2cUnacked[:chunk]
	seq := s.s2cUnackedSeq
	ack := s.wireAckNumberLocked()
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
	pkt := buildIPTCPPacket(
		s.flow.dstAddr, s.flow.srcAddr,
		s.flow.dstPort, s.flow.srcPort,
		seq, ack,
		header.TCPFlagPsh|header.TCPFlagAck,
		s.advertisedWindowFieldLocked(),
		payload,
		opts,
	)
	s.mu.Unlock()

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
	s.ensureS2CWake()
	// P6-B1: backend dial is async after SYN-ACK; C2S may start the pump before bindRemote.
	// Wait on wake/close only (no 2ms poll): bindRemote + close signal s2cWake.
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
		}
		if s.closed.Load() {
			return
		}
	}
	readSz := remoteReadBuf
	if mss := int(s.clientMSS); mss > 0 {
		if readSz < 32*mss {
			readSz = 32 * mss
		}
		// No 16×MSS cap: that shallow-filled S2C under onward RTT (P6-SC).
	}
	buf := make([]byte, readSz)
	maxSeg := maxSegmentPayloadForFlow(s.clientMSS, s.flow)
	var rtoTimer *time.Timer
	defer func() {
		if rtoTimer != nil {
			rtoTimer.Stop()
		}
	}()
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
				// In-place: finish segment/preClient handling before the next Read.
				// Escape copies stay in appendS2CUnackedLocked + buildIPTCPPacket (+ preClient append).
				// Dual-buffer not needed — pump is strictly process-before-Read.
				data = buf[:n]
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
			// Event-driven: wait for C2S payload / allow flag (handleSegment signals).
			select {
			case <-ctx.Done():
				return
			case <-s.s2cWake:
			}
			if s.closed.Load() {
				return
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
				if rtoTimer == nil {
					rtoTimer = time.NewTimer(rtoWait)
				} else {
					if !rtoTimer.Stop() {
						select {
						case <-rtoTimer.C:
						default:
						}
					}
					rtoTimer.Reset(rtoWait)
				}
				select {
				case <-ctx.Done():
					return
				case <-s.s2cWake:
				case <-rtoTimer.C:
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
			ack := s.wireAckNumberLocked()
			wnd := s.advertisedWindowFieldLocked()
			opts := s.buildTimestampOptionLocked()
			s.mu.Unlock()
			pkt := buildIPTCPPacket(
				s.flow.dstAddr, s.flow.srcAddr,
				s.flow.dstPort, s.flow.srcPort,
				seq, ack,
				header.TCPFlagPsh|header.TCPFlagAck,
				wnd,
				payload,
				opts,
			)
			// Interactive / control S2C (iperf results): after a quiet gap, prefer
			// writeCh so results are not buried behind elephant downloadCh under
			// host-TUN -P≥3. First segment and sustained bulk stay on downloadCh
			// (zero s2cLastEnqueue must NOT look like a gap — that reordered SEQ).
			const s2cInteractiveGap = 20 * time.Millisecond
			usePrio := !s.s2cLastEnqueue.IsZero() && time.Since(s.s2cLastEnqueue) >= s2cInteractiveGap
			s.s2cLastEnqueue = time.Now()
			var err error
			if usePrio {
				err = s.f.enqueueWrite(pkt)
			} else {
				err = s.f.enqueueDownload(pkt)
			}
			if err != nil {
				return
			}
			off += chunk
		}
	}
}

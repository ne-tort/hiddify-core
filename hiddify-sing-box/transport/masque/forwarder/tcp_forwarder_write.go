package forwarder

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/sagernet/sing-box/transport/masque/connectip/losslocus"
	"github.com/sagernet/sing-box/transport/masque/connectip/relaystats"
)

// P6-D1 / P6-C2: coalesce downloadCh drain before one Fountain/NoWake flush.
//
// downloadCh: short coalesce wait forms ~MSS×N batches (required for local L1
// attrib; pure non-blocking micro-batches → download_q_high→3k / ~250 Mbit/s).
//
// writeCh ACK/control: immediate WritePacket wake (not NoWake batch). True
// AddNoWake on ACKs delayed the nested TCP clock and regressed WAN UP
// ~42→~17 (RTO↑). DATA S2C still uses NoWake+Flush below.
const (
	downloadBatchMaxPkts      = 32
	downloadBatchCoalesceWait = 400 * time.Microsecond
	downloadBatchMinWireBytes = 32 * 1024
	// Mid-batch writeCh drain every N DATA under sendMu. 0 = disabled mid-batch
	// (only bounded drainWriteChLocked after Flush) — mid-batch Flush starved H2
	// MultiShort under short-storm ACK floods.
	ackInterleaveEvery = 0
	// Max ACK/control segments drained per mid-batch interleave (when enabled).
	writeChDrainMax = 2
	// Max writeCh packets drained before each select. Unbounded prefer starved
	// MultiShort bulk; 0 breaks control-before-download unit gate.
	writeChPreferMax = 2
	// Soft ACK admission: when writeCh is this deep, drop pure ACKs (cumulative
	// supersede). Avoids demux HOL / results bury under iperf -P≥3 upload ACK storm.
	writeChAckAdmitHigh = 512
)

func (f *packetForwarder) egressStopped() bool {
	select {
	case <-f.writeStopped:
		return true
	case <-f.downloadStopped:
		return true
	default:
		return false
	}
}

// stopPlaneFromEgress unblocks ReadPacket and ends RouteConnectIPBlocked after
// peer half-close / closed plane. Without this, sendPacketNow used to swallow
// IsBenignEgressTeardownError as success and orphan UDP pumps (P4-5 sticky dual).
func (f *packetForwarder) stopPlaneFromEgress() {
	if f == nil || f.conn == nil {
		return
	}
	f.planeStopOnce.Do(func() {
		losslocus.RecordServerS2PlaneStopFromEgress()
		_ = f.conn.Close()
	})
}

// egressWriteKillsPlane: only benign teardown or structured plane-fatal may
// stop the whole CONNECT-IP plane. Transient write fails drop the segment.
func egressWriteKillsPlane(err error) bool {
	if err == nil {
		return false
	}
	if mcip.IsBenignEgressTeardownError(err) {
		return true
	}
	return mcip.IsConnectIPPlaneFatalForRecycle(err)
}

func (f *packetForwarder) sendWriteChPkt(pkt []byte) {
	f.o.WriteQueueMetrics.noteDequeued()
	f.sendWriteChDequeued(pkt)
}

// sendWriteChDequeued sends one already-dequeued writeCh packet (ACK/control)
// with wake. Leftovers from ACK coalesce are already dequeued — do not
// noteDequeued again.
func (f *packetForwarder) sendWriteChDequeued(pkt []byte) {
	coalesced, leftover := f.coalesceQueuedAckOnly(pkt)
	err := f.sendPacketNow(coalesced)
	if err != nil {
		if mcip.IsRetryablePacketWriteError(err) {
			select {
			case <-f.writeStopped:
				returnPacket(coalesced)
			case f.writeCh <- coalesced:
			}
			if leftover != nil {
				select {
				case <-f.writeStopped:
					returnPacket(leftover)
				case f.writeCh <- leftover:
				}
			}
			return
		}
		returnPacket(coalesced)
		if leftover != nil {
			returnPacket(leftover)
		}
		if egressWriteKillsPlane(err) {
			f.stopPlaneFromEgress()
		} else {
			relaystats.RecordS2CWriteFail()
		}
		return
	}
	returnPacket(coalesced)
	if leftover != nil {
		f.sendWriteChDequeued(leftover)
	}
}

func (f *packetForwarder) sendDownloadChPkt(pkt []byte) {
	f.o.DownloadQueueMetrics.noteDequeued()
	pkts := f.collectDownloadBatch(pkt)
	err := f.sendCoalescedBatch(pkts)
	if err != nil {
		if mcip.IsRetryablePacketWriteError(err) {
			for _, p := range pkts {
				select {
				case <-f.downloadStopped:
					returnPacket(p)
				case f.downloadCh <- p:
				}
			}
			return
		}
		for _, p := range pkts {
			returnPacket(p)
		}
		if egressWriteKillsPlane(err) {
			f.stopPlaneFromEgress()
		} else {
			relaystats.RecordS2CWriteFail()
		}
		return
	}
	for _, p := range pkts {
		returnPacket(p)
	}
}

func (f *packetForwarder) collectDownloadBatch(first []byte) [][]byte {
	pkts := [][]byte{first}
	wireBytes := len(first)
	if downloadBatchMaxPkts <= 1 {
		return pkts
	}
	// Small S2C (iperf results / control JSON): no coalesce wait — deliver ASAP
	// under upload ACK storms that otherwise bury downloadCh for 400µs×N.
	if pl := wireTCPPayloadLen(first); pl > 0 && pl <= 256 {
		return pkts
	}
	// Timer select (not Gosched spin): wait up to coalesce window for more DATA.
	// Do not drain writeCh here — that starves downloadCh under short-storm ACK
	// floods (MultiShort). Control ACK still drains in runEgressLoop + after Flush.
	timer := time.NewTimer(downloadBatchCoalesceWait)
	defer timer.Stop()
	for len(pkts) < downloadBatchMaxPkts && wireBytes < downloadBatchMinWireBytes {
		select {
		case pkt, ok := <-f.downloadCh:
			if !ok {
				return pkts
			}
			f.o.DownloadQueueMetrics.noteDequeued()
			pkts = append(pkts, pkt)
			wireBytes += len(pkt)
		case <-timer.C:
			return pkts
		}
	}
	return pkts
}

func (f *packetForwarder) writeChHasPending() bool {
	if f == nil || f.writeCh == nil {
		return false
	}
	if f.o.WriteQueueMetrics != nil && f.o.WriteQueueMetrics.Depth.Load() > 0 {
		return true
	}
	return len(f.writeCh) > 0
}

// drainWriteChLocked drains up to writeChDrainMax ACK/control while holding sendMu.
func (f *packetForwarder) drainWriteChLocked() {
	for n := 0; n < writeChDrainMax; n++ {
		select {
		case pkt, ok := <-f.writeCh:
			if !ok {
				return
			}
			f.o.WriteQueueMetrics.noteDequeued()
			coalesced, leftover := f.coalesceQueuedAckOnly(pkt)
			err := f.writePacketRelayLocked(f.conn.WritePacket, coalesced)
			returnPacket(coalesced)
			if leftover != nil {
				if err == nil {
					err = f.writePacketRelayLocked(f.conn.WritePacket, leftover)
				}
				returnPacket(leftover)
			}
			if err != nil {
				if mcip.IsRetryablePacketWriteError(err) {
					return
				}
				if egressWriteKillsPlane(err) {
					f.stopPlaneFromEgress()
				} else {
					relaystats.RecordS2CWriteFail()
				}
				return
			}
		default:
			return
		}
	}
}

func (f *packetForwarder) sendCoalescedBatch(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	// Single small control/results segment: wake WritePacket (not NoWake batch).
	if len(pkts) == 1 {
		if pl := wireTCPPayloadLen(pkts[0]); pl > 0 && pl <= 256 {
			return f.sendPacketNow(pkts[0])
		}
	}
	if cw, ok := f.conn.(packetPlaneCoalescedWriter); ok {
		f.sendMu.Lock()
		defer f.sendMu.Unlock()
		for i, pkt := range pkts {
			if err := f.writePacketRelayLocked(cw.WritePacketNoWake, pkt); err != nil {
				return err
			}
			// Mid-batch interleave: every N DATA Flush+drain. N=0 disables (MultiShort).
			if n := ackInterleaveEvery; n > 0 && (i+1)%n == 0 && f.writeChHasPending() {
				cw.FlushOutgoingDatagramSend()
				relaystats.RecordS2CBatchFlush()
				f.drainWriteChLocked()
			}
		}
		cw.FlushOutgoingDatagramSend()
		relaystats.RecordS2CBatchFlush()
		// Bounded drain: nested bulk ACKs under sendMu without Flush×storm.
		f.drainWriteChLocked()
		return nil
	}
	for _, pkt := range pkts {
		if err := f.sendPacketNow(pkt); err != nil {
			return err
		}
	}
	return nil
}

// runEgressLoop: bounded writeCh prefer, then forced downloadCh turn when bulk
// pending (iperf results / S2C DATA must not lose every select to ACK flood).
func (f *packetForwarder) runEgressLoop(ctx context.Context, done chan struct{}) {
	defer close(done)
	for {
		if f.egressStopped() {
			return
		}
		for i := 0; i < writeChPreferMax && f.tryDrainWriteCh(); i++ {
		}
		if len(f.downloadCh) > 0 {
			select {
			case <-ctx.Done():
				return
			case <-f.writeStopped:
				return
			case <-f.downloadStopped:
				return
			case pkt, ok := <-f.downloadCh:
				if !ok {
					return
				}
				f.sendDownloadChPkt(pkt)
			}
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-f.writeStopped:
			return
		case <-f.downloadStopped:
			return
		case pkt, ok := <-f.writeCh:
			if !ok {
				return
			}
			f.sendWriteChPkt(pkt)
		case pkt, ok := <-f.downloadCh:
			if !ok {
				return
			}
			f.sendDownloadChPkt(pkt)
		}
	}
}

func (f *packetForwarder) tryDrainWriteCh() bool {
	select {
	case pkt, ok := <-f.writeCh:
		if !ok {
			return false
		}
		f.sendWriteChPkt(pkt)
		return true
	default:
		return false
	}
}

func (f *packetForwarder) writeLoopStopped() bool {
	select {
	case <-f.writeStopped:
		return true
	default:
		return false
	}
}

func (f *packetForwarder) enqueueWrite(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	if f.writeCh == nil {
		err := f.sendPacketNow(pkt)
		returnPacket(pkt)
		return err
	}
	if f.writeLoopStopped() {
		returnPacket(pkt)
		losslocus.RecordServerS2DiscardTeardown()
		return net.ErrClosed
	}
	// Soft admission: deep writeCh under upload -P≥3 — drop pure ACK (next seg
	// brings a newer cumulative). Never block demux waiting for queue space.
	if _, isACK := ackOnlyFlow(pkt); isACK {
		depth := len(f.writeCh)
		if f.o.WriteQueueMetrics != nil {
			if d := int(f.o.WriteQueueMetrics.Depth.Load()); d > depth {
				depth = d
			}
		}
		if depth >= writeChAckAdmitHigh {
			returnPacket(pkt)
			relaystats.RecordS2CAckAdmitDrop()
			return nil
		}
	}
	select {
	case f.writeCh <- pkt:
		f.o.WriteQueueMetrics.noteEnqueued()
		relaystats.RecordS2CEnqueue()
		if f.o.WriteQueueMetrics != nil {
			relaystats.NoteWriteQHigh(f.o.WriteQueueMetrics.Depth.Load())
		}
		return nil
	default:
		// writeCh full: never park demux on sendMu or channel wait.
		if _, ok := ackOnlyFlow(pkt); ok {
			if f.sendMu.TryLock() {
				err := f.writePacketRelayLocked(f.conn.WritePacket, pkt)
				f.sendMu.Unlock()
				returnPacket(pkt)
				return err
			}
			returnPacket(pkt)
			relaystats.RecordS2CAckAdmitDrop()
			return nil
		}
		select {
		case f.writeCh <- pkt:
			f.o.WriteQueueMetrics.noteEnqueued()
			relaystats.RecordS2CEnqueue()
			if f.o.WriteQueueMetrics != nil {
				relaystats.NoteWriteQHigh(f.o.WriteQueueMetrics.Depth.Load())
			}
			return nil
		case <-f.writeStopped:
			returnPacket(pkt)
			losslocus.RecordServerS2DiscardTeardown()
			return net.ErrClosed
		}
	}
}

func (f *packetForwarder) writeRaw(pkt []byte) error {
	return f.enqueueWrite(pkt)
}

// enqueueDownload pipelines remote→client bulk DATA (TCP download + UDP S2C replies).
// FIN also uses downloadCh (not writeCh) so it cannot overtake queued S2C DATA.
// Interactive/control S2C (iperf results) is routed to writeCh from the S2C pump
// after a quiet gap — see pumpRemoteToClient — so small results are not buried
// behind elephant downloadCh FIFO under host-TUN iperf -P≥3.
// Control ACKs stay on writeCh via enqueueWrite / writeRaw.
// P4-3: UDP must not share writeCh with TCP control under WAN backpressure.
func (f *packetForwarder) enqueueDownload(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	if f.downloadCh == nil {
		err := f.sendPacketNow(pkt)
		returnPacket(pkt)
		return err
	}
	if f.egressStopped() {
		returnPacket(pkt)
		losslocus.RecordServerS2DiscardTeardown()
		return net.ErrClosed
	}
	if err := f.tryEnqueueDownload(pkt); err != nil {
		returnPacket(pkt)
		if errors.Is(err, net.ErrClosed) {
			losslocus.RecordServerS2DiscardTeardown()
		}
		return err
	}
	f.o.DownloadQueueMetrics.noteEnqueued()
	relaystats.RecordS2CEnqueue()
	if f.o.DownloadQueueMetrics != nil {
		relaystats.NoteDownloadQHigh(f.o.DownloadQueueMetrics.Depth.Load())
	}
	return nil
}

// tryEnqueueDownload sends to downloadCh; recovers send-on-closed (test teardown race).
func (f *packetForwarder) tryEnqueueDownload(pkt []byte) (err error) {
	defer func() {
		if recover() != nil {
			err = net.ErrClosed
		}
	}()
	select {
	case <-f.downloadStopped:
		return net.ErrClosed
	case f.downloadCh <- pkt:
		return nil
	default:
		select {
		case <-f.downloadStopped:
			return net.ErrClosed
		case f.downloadCh <- pkt:
			return nil
		}
	}
}

// writeDownloadDirect sends one download DATA segment synchronously (unit tests).
func (f *packetForwarder) writeDownloadDirect(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	err := f.sendPacketNow(pkt)
	returnPacket(pkt)
	return err
}

func (f *packetForwarder) peerPrefixesCached() []netip.Prefix {
	if v := f.peerPrefixes.Load(); v != nil {
		if p, ok := v.([]netip.Prefix); ok {
			return p
		}
	}
	p := f.conn.CurrentPeerPrefixes()
	f.peerPrefixes.Store(p)
	return p
}

// sendPacketNow writes one packet to the CONNECT-IP plane with retry/backoff.
// Must be serialized: runEgressLoop owns the sole PacketPlaneConn writer.
func (f *packetForwarder) sendPacketNow(pkt []byte) error {
	f.sendMu.Lock()
	defer f.sendMu.Unlock()
	return f.writePacketRelayLocked(f.conn.WritePacket, pkt)
}

type packetWriteFn func([]byte) ([]byte, error)

func (f *packetForwarder) writePacketRelayLocked(write packetWriteFn, pkt []byte) error {
	p := RewriteOutgoingPeerDst(pkt, f.peerPrefixesCached())
	for i := 0; i < icmpRelayMax; i++ {
		var icmp []byte
		var err error
		for attempt := 0; attempt < writePacketMaxPersist; attempt++ {
			icmp, err = write(p)
			if err == nil {
				break
			}
			if mcip.IsBenignEgressTeardownError(err) {
				relaystats.RecordS2CWriteFail()
				return err
			}
			if !mcip.IsRetryablePacketWriteError(err) {
				relaystats.RecordS2CWriteFail()
				return err
			}
			backoff := attempt
			if backoff > 15 {
				backoff = 15
			}
			time.Sleep(time.Duration(1+backoff) * time.Millisecond)
		}
		if err != nil {
			relaystats.RecordS2CWriteFail()
			return err
		}
		if len(icmp) == 0 {
			relaystats.RecordS2COut(len(pkt))
			return nil
		}
		p = icmp
	}
	relaystats.RecordS2CWriteFail()
	return errors.New("masque: connect-ip forwarder: ICMP relay exceeded")
}

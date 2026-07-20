package forwarder

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
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
		_ = f.conn.Close()
	})
}

func (f *packetForwarder) sendWriteChPkt(pkt []byte) {
	f.o.WriteQueueMetrics.noteDequeued()
	pkt = f.coalesceQueuedAckOnly(pkt)
	err := f.sendPacketNow(pkt)
	if err != nil {
		if mcip.IsRetryablePacketWriteError(err) {
			select {
			case <-f.writeStopped:
				returnPacket(pkt)
			case f.writeCh <- pkt:
			}
			return
		}
		// Benign teardown or hard write fault: stop the plane (do not drop forever).
		returnPacket(pkt)
		f.stopPlaneFromEgress()
		return
	}
	returnPacket(pkt)
}

func (f *packetForwarder) sendDownloadChPkt(pkt []byte) {
	f.o.DownloadQueueMetrics.noteDequeued()
	pkts := f.collectDownloadBatch(pkt)
	err := f.sendDownloadBatch(pkts)
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
		f.stopPlaneFromEgress()
		return
	}
	for _, p := range pkts {
		returnPacket(p)
	}
}

func (f *packetForwarder) collectDownloadBatch(first []byte) [][]byte {
	pkts := [][]byte{first}
	for {
		select {
		case pkt, ok := <-f.downloadCh:
			if !ok {
				return pkts
			}
			f.o.DownloadQueueMetrics.noteDequeued()
			pkts = append(pkts, pkt)
		default:
			return pkts
		}
	}
}

func (f *packetForwarder) sendDownloadBatch(pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	if cw, ok := f.conn.(packetPlaneCoalescedWriter); ok {
		f.sendMu.Lock()
		defer f.sendMu.Unlock()
		for _, pkt := range pkts {
			if err := f.writePacketRelayLocked(cw.WritePacketNoWake, pkt); err != nil {
				return err
			}
		}
		cw.FlushOutgoingDatagramSend()
		return nil
	}
	for _, pkt := range pkts {
		if err := f.sendPacketNow(pkt); err != nil {
			return err
		}
	}
	return nil
}

// runEgressLoop drains writeCh (control) before downloadCh (bulk DATA). Parallel loops
// previously raced on sendMu and could deliver iperf -R bulk before params ACK on wire.
func (f *packetForwarder) runEgressLoop(ctx context.Context, done chan struct{}) {
	defer close(done)
	for {
		if f.egressStopped() {
			return
		}
		for f.tryDrainWriteCh() {
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
		return net.ErrClosed
	}
	select {
	case f.writeCh <- pkt:
		f.o.WriteQueueMetrics.noteEnqueued()
		return nil
	default:
		select {
		case f.writeCh <- pkt:
			f.o.WriteQueueMetrics.noteEnqueued()
			return nil
		case <-f.writeStopped:
			returnPacket(pkt)
			return net.ErrClosed
		}
	}
}

func (f *packetForwarder) writeRaw(pkt []byte) error {
	return f.enqueueWrite(pkt)
}

// enqueueDownload pipelines remote→client bulk DATA (TCP download + UDP S2C replies).
// Control segments (ACK, FIN) stay on writeCh via enqueueWrite / writeRaw.
// P4-3: UDP must not share writeCh(512) with TCP control under WAN backpressure.
func (f *packetForwarder) enqueueDownload(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	if f.downloadCh == nil {
		err := f.sendPacketNow(pkt)
		returnPacket(pkt)
		return err
	}
	select {
	case <-f.downloadStopped:
		returnPacket(pkt)
		return net.ErrClosed
	case f.downloadCh <- pkt:
		f.o.DownloadQueueMetrics.noteEnqueued()
		return nil
	default:
		select {
		case <-f.downloadStopped:
			returnPacket(pkt)
			return net.ErrClosed
		case f.downloadCh <- pkt:
			f.o.DownloadQueueMetrics.noteEnqueued()
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
				return err
			}
			if !mcip.IsRetryablePacketWriteError(err) {
				return err
			}
			backoff := attempt
			if backoff > 15 {
				backoff = 15
			}
			time.Sleep(time.Duration(1+backoff) * time.Millisecond)
		}
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

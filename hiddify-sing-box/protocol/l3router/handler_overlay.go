package l3routerendpoint

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	rt "github.com/sagernet/sing-box/common/l3router"
	"github.com/sagernet/sing/common/buf"
	singbufio "github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// egressWriteDeadlineMinInterval avoids SetWriteDeadline (typically one syscall per call on TCP) on every
// forwarded datagram — that capped effective throughput on high-PPS overlays.
const egressWriteDeadlineMinInterval = 400 * time.Millisecond

// egressWriteBlockBudget is the maximum duration a single blocked WritePacket may wait before the deadline fires.
const egressWriteBlockBudget = 30 * time.Second

func (e *Endpoint) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	e.logger.WarnContext(ctx, "[l3router] inbound TCP is unsupported; expected UDP raw IP overlay")
	N.CloseOnHandshakeFailure(conn, onClose, os.ErrInvalid)
}

// NewPacketConnectionEx is the only entry that ties sing-box inbound identity to l3router:
// metadata.User → SessionKey → bindUserSession (Route.user). common/l3router never sees User.
func (e *Endpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if metadata.User == "" {
		e.logger.WarnContext(ctx, "[l3router] missing inbound user/session; drop")
		conn.Close()
		if onClose != nil {
			onClose(os.ErrInvalid)
		}
		return
	}
	sk := rt.SessionKey(metadata.User)
	e.enterSession(sk)
	generation := e.registerSession(sk, conn)
	e.logger.TraceContext(ctx, "[l3router] NewPacketConnectionEx registered",
		"user", metadata.User,
		"generation", generation,
		"destination", metadata.Destination.String(),
	)
	go func() {
		defer e.leaveSessionWithGeneration(sk, generation)
		defer e.unregisterSession(sk, conn, generation)
		e.runOverlay(ctx, conn, sk, generation, onClose)
	}()
}

func (e *Endpoint) runOverlay(ctx context.Context, conn N.PacketConn, ingressSession rt.SessionKey, generation uint64, onClose N.CloseHandlerFunc) {
	const detailFlushEvery = 64
	var localDropFilterSource uint64
	var localDropFilterDest uint64
	var localFragmentDrops uint64
	flushDetail := func(force bool) {
		if !e.detailCountersEnabled() {
			localDropFilterSource = 0
			localDropFilterDest = 0
			localFragmentDrops = 0
			return
		}
		total := localDropFilterSource + localDropFilterDest + localFragmentDrops
		if !force && total < detailFlushEvery {
			return
		}
		if localDropFilterSource > 0 {
			if e.detailCountersEnabled() {
				e.dropFilterSource.Add(localDropFilterSource)
			}
			localDropFilterSource = 0
		}
		if localDropFilterDest > 0 {
			if e.detailCountersEnabled() {
				e.dropFilterDest.Add(localDropFilterDest)
			}
			localDropFilterDest = 0
		}
		if localFragmentDrops > 0 {
			if e.detailCountersEnabled() {
				e.fragmentDrops.Add(localFragmentDrops)
			}
			localFragmentDrops = 0
		}
	}
	defer flushDetail(true)
	var loggedFirstRx bool
	for {
		buffer := buf.NewPacket()
		_, err := conn.ReadPacket(buffer)
		if err != nil {
			flushDetail(true)
			buffer.Release()
			if onClose != nil {
				onClose(err)
			}
			return
		}
		pkt := buffer.Bytes()
		if len(pkt) == 0 {
			buffer.Release()
			continue
		}
		if !loggedFirstRx {
			loggedFirstRx = true
			e.logger.TraceContext(ctx, "[l3router] first non-empty overlay rx",
				"session", string(ingressSession),
				"generation", generation,
				"len", len(pkt),
			)
		}
		e.markSessionRxWarm(ingressSession, generation)
		e.addIngressPackets(1)

		dec, egressSession, hasForward := e.resolveForwardDecision(pkt, ingressSession)
		if !hasForward {
			if dec.Action == rt.ActionForward && dec.EgressPeerID != 0 {
				if e.queuePendingForPeer(dec.EgressPeerID, buffer) {
					e.addDropEgressOffline(1)
					continue
				}
			}
			buffer.Release()
			e.addDropPackets(1)
			switch dec.DropReason {
			case rt.DropNoIngressRoute:
				e.addDropNoIngressRoute(1)
			case rt.DropNoEgressRoute:
				e.addDropNoEgressRoute(1)
			case rt.DropFilterSource:
				localDropFilterSource++
			case rt.DropFilterDestination:
				localDropFilterDest++
			default:
				e.addDropDecisionOther(1)
			}
			flushDetail(false)
			continue
		}
		if e.fragmentPolicy == fragmentPolicyDrop && isIPv4Fragment(pkt) {
			buffer.Release()
			localFragmentDrops++
			e.addDropPackets(1)
			flushDetail(false)
			continue
		}
		queued, queueFull := e.enqueueEgress(egressSession, buffer)
		if !queued {
			// enqueueEgress does not Release on failure; caller owns payload.
			buffer.Release()
			e.addDropPackets(1)
			if queueFull {
				e.addDropQueueOverflow(1)
			} else {
				e.addDropNoSession(1)
				e.addDropQueueNoSession(1)
			}
			continue
		}
		e.addForwardPackets(1)
		// buffer ownership transferred to egressWorker (sing managed pool).
	}
}

func (e *Endpoint) resolveForwardDecision(packet []byte, ingressSession rt.SessionKey) (rt.Decision, rt.SessionKey, bool) {
	ingressPeer, ok := e.ingressPeerForSession(ingressSession)
	if !ok {
		return rt.Decision{Action: rt.ActionDrop, DropReason: rt.DropNoIngressRoute}, "", false
	}
	dec := e.engine.HandleIngressPeer(packet, ingressPeer)
	if dec.Action != rt.ActionForward {
		return dec, "", false
	}
	session, ok := e.egressSessionForPeer(dec.EgressPeerID)
	if ok && session != ingressSession {
		return dec, session, true
	}
	// Keep ActionForward + EgressPeerID so caller can buffer briefly while session is coming up.
	return rt.Decision{Action: rt.ActionForward, EgressPeerID: dec.EgressPeerID, DropReason: rt.DropNoEgressRoute}, "", false
}

// enqueueEgress queues payload for the egress session writer. On success, ownership moves to the worker.
// On failure, the caller must Release the buffer. Returns queueFull=true only when the egress queue rejected
// the datagram after an eviction attempt (real overflow).
func (e *Endpoint) enqueueEgress(session rt.SessionKey, payload *buf.Buffer) (queued bool, queueFull bool) {
	// Avoid spawning idle egress workers for unknown SessionKeys: if nobody has ever entered as this user,
	// there is no transient bind/register window to buffer for.
	if e.sessionConn(session) == nil {
		e.refMu.Lock()
		hasUserRef := e.userRef[session] > 0
		e.refMu.Unlock()
		if !hasUserRef {
			return false, false
		}
	}
	if e.scheduler == nil {
		return false, true
	}
	queued, queueFull, _ = e.scheduler.enqueue(session, payload, e.overflowPolicy)
	return queued, queueFull
}

func writePacketBuffer(out N.PacketConn, payload *buf.Buffer, destination M.Socksaddr) (bool, error) {
	_, err := singbufio.WritePacketBuffer(out, payload, destination)
	return err == nil, err
}

func isTimeoutError(err error) bool {
	type timeout interface{ Timeout() bool }
	if te, ok := err.(timeout); ok && te.Timeout() {
		return true
	}
	return false
}

func isIPv4Fragment(pkt []byte) bool {
	if len(pkt) < 20 || (pkt[0]>>4) != 4 {
		return false
	}
	flagsAndOffset := binary.BigEndian.Uint16(pkt[6:8])
	moreFragments := (flagsAndOffset & 0x2000) != 0
	fragmentOffset := (flagsAndOffset & 0x1fff) != 0
	return moreFragments || fragmentOffset
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	e.logger.WarnContext(ctx, "[l3router] outbound ", network, " dial to ", destination, " is unsupported")
	return nil, os.ErrInvalid
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	e.logger.WarnContext(ctx, "[l3router] outbound UDP listen to ", destination, " is unsupported")
	return nil, os.ErrInvalid
}

package l3routerendpoint

import (
	"slices"
	"time"

	rt "github.com/sagernet/sing-box/common/l3router"
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

func (e *Endpoint) enterSession(sk rt.SessionKey) {
	e.refMu.Lock()
	defer e.refMu.Unlock()
	if e.activeUserSession == nil {
		e.activeUserSession = make(map[string]rt.SessionKey)
	}
	if e.sessionIngressPeer == nil {
		e.sessionIngressPeer = make(map[rt.SessionKey]rt.PeerID)
	}
	if e.peerEgressSession == nil {
		e.peerEgressSession = make(map[rt.PeerID]rt.SessionKey)
	}
	// Single-session policy: last connection becomes active owner for this user.
	e.userRef[sk] = 1
	user := string(sk)
	e.sessMu.Lock()
	e.activeUserSession[user] = sk
	e.sessMu.Unlock()
	e.bindUserSession(user, sk)
}

func (e *Endpoint) leaveSession(sk rt.SessionKey) {
	e.refMu.Lock()
	generation := e.sessionGeneration[sk]
	e.refMu.Unlock()
	e.leaveSessionWithGeneration(sk, generation)
}

func (e *Endpoint) leaveSessionWithGeneration(sk rt.SessionKey, generation uint64) {
	e.refMu.Lock()
	defer e.refMu.Unlock()
	currentGen, ok := e.sessionGeneration[sk]
	if !ok || currentGen != generation {
		return
	}
	user := string(sk)
	delete(e.userRef, sk)
	delete(e.sessionGeneration, sk)
	delete(e.sessionRxWarm, sk)
	delete(e.sessionTxWarm, sk)
	e.sessMu.Lock()
	delete(e.activeUserSession, user)
	e.sessMu.Unlock()
	e.unbindUserSession(user, sk)
}

func (e *Endpoint) bindUserSession(user string, sk rt.SessionKey) {
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	if e.userPeers == nil {
		return
	}
	peerIDs := e.userPeers[user]
	if len(peerIDs) == 0 {
		delete(e.sessionIngressPeer, sk)
		e.publishBindingSnapshotLocked()
		return
	}
	keys := make([]int, 0, len(peerIDs))
	for rid := range peerIDs {
		keys = append(keys, int(rid))
	}
	slices.Sort(keys)
	// Deterministic ingress peer selection for user with multiple peers.
	e.sessionIngressPeer[sk] = rt.PeerID(keys[0])
	for _, rid := range keys {
		e.peerEgressSession[rt.PeerID(rid)] = sk
	}
	e.publishBindingSnapshotLocked()
}

func (e *Endpoint) unbindUserSession(user string, sk rt.SessionKey) {
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	peerIDs := e.userPeers[user]
	for rid := range peerIDs {
		if ingress, ok := e.sessionIngressPeer[sk]; ok && ingress == rt.PeerID(rid) {
			delete(e.sessionIngressPeer, sk)
		}
		peer := rt.PeerID(rid)
		if mapped, ok := e.peerEgressSession[peer]; ok && mapped == sk {
			delete(e.peerEgressSession, peer)
		}
	}
	e.publishBindingSnapshotLocked()
}

func (e *Endpoint) registerSession(sk rt.SessionKey, conn N.PacketConn) uint64 {
	var oldConn N.PacketConn
	e.refMu.Lock()
	generation := e.nextGeneration.Add(1)
	e.sessionGeneration[sk] = generation
	delete(e.sessionRxWarm, sk)
	delete(e.sessionTxWarm, sk)
	e.refMu.Unlock()
	e.sessMu.Lock()
	if old := e.sessions[sk]; old != nil {
		oldConn = old
	}
	e.sessions[sk] = conn
	e.sessMu.Unlock()
	e.onSessionReady(sk, generation, oldConn != nil)
	if oldConn != nil {
		oldConn.Close()
	}
	return generation
}

func (e *Endpoint) unregisterSession(sk rt.SessionKey, conn N.PacketConn, generation uint64) {
	e.refMu.Lock()
	currentGen, ok := e.sessionGeneration[sk]
	e.refMu.Unlock()
	if !ok || currentGen != generation {
		return
	}
	e.sessMu.Lock()
	if c, ok := e.sessions[sk]; ok && c == conn {
		delete(e.sessions, sk)
	}
	e.sessMu.Unlock()
}

func (e *Endpoint) sessionConn(sk rt.SessionKey) N.PacketConn {
	e.sessMu.RLock()
	defer e.sessMu.RUnlock()
	return e.sessions[sk]
}

func (e *Endpoint) ingressPeerForSession(sk rt.SessionKey) (rt.PeerID, bool) {
	snapshot := e.bindings.Load()
	if snapshot == nil {
		return 0, false
	}
	peer, ok := snapshot.ingress[sk]
	return peer, ok
}

func (e *Endpoint) egressSessionForPeer(peer rt.PeerID) (rt.SessionKey, bool) {
	snapshot := e.bindings.Load()
	if snapshot == nil {
		return "", false
	}
	session, ok := snapshot.egress[peer]
	return session, ok
}

func (e *Endpoint) onSessionReady(sk rt.SessionKey, generation uint64, replaced bool) {
	e.refMu.Lock()
	current := e.sessionGeneration[sk]
	e.refMu.Unlock()
	if current != generation {
		return
	}
	e.sessionReadyTransitions.Add(1)
	if replaced {
		e.sessionReplacements.Add(1)
	}
	e.logger.TraceContext(e.ctx, "[l3router] onSessionReady",
		"session", string(sk),
		"generation", generation,
		"replaced", replaced,
	)
	e.flushPendingForSession(sk)
}

func (e *Endpoint) markSessionRxWarm(sk rt.SessionKey, generation uint64) {
	e.refMu.Lock()
	defer e.refMu.Unlock()
	if e.sessionGeneration[sk] != generation {
		return
	}
	if e.sessionRxWarm[sk] {
		return
	}
	e.sessionRxWarm[sk] = true
	e.sessionRxWarmTransitions.Add(1)
}

func (e *Endpoint) markSessionTxWarm(sk rt.SessionKey) {
	e.refMu.Lock()
	defer e.refMu.Unlock()
	if e.sessionGeneration[sk] == 0 {
		return
	}
	if e.sessionTxWarm[sk] {
		return
	}
	e.sessionTxWarm[sk] = true
	e.sessionTxWarmTransitions.Add(1)
}

func (e *Endpoint) queuePendingForPeer(peer rt.PeerID, payload *buf.Buffer) bool {
	e.pendingMu.Lock()
	defer e.pendingMu.Unlock()
	queue := e.pendingByPeer[peer]
	cutoff := time.Now().Add(-e.pendingTTL)
	if len(queue) > 0 {
		filtered := queue[:0]
		for _, env := range queue {
			if env == nil || env.payload == nil || env.enqueueAt.Before(cutoff) {
				if env != nil && env.payload != nil {
					env.payload.Release()
				}
				continue
			}
			filtered = append(filtered, env)
		}
		queue = filtered
	}
	if len(queue) >= e.pendingPerPeer {
		old := queue[0]
		if old != nil && old.payload != nil {
			old.payload.Release()
		}
		copy(queue, queue[1:])
		queue = queue[:len(queue)-1]
	}
	queue = append(queue, &pendingEnvelope{payload: payload, enqueueAt: time.Now()})
	e.pendingByPeer[peer] = queue
	return true
}

func (e *Endpoint) flushPendingForSession(session rt.SessionKey) {
	e.pendingMu.Lock()
	defer e.pendingMu.Unlock()
	now := time.Now()
	for peer, queue := range e.pendingByPeer {
		mappedSession, ok := e.egressSessionForPeer(peer)
		if !ok || mappedSession != session {
			continue
		}
		for _, env := range queue {
			if env == nil || env.payload == nil {
				continue
			}
			if now.Sub(env.enqueueAt) > e.pendingTTL {
				env.payload.Release()
				continue
			}
			queued, queueFull := e.enqueueEgress(session, env.payload)
			if !queued {
				env.payload.Release()
				e.addDropPackets(1)
				if queueFull {
					e.addDropQueueOverflow(1)
				} else {
					e.addDropNoSession(1)
					e.addDropQueueNoSession(1)
				}
			}
		}
		delete(e.pendingByPeer, peer)
	}
}

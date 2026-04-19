package l3routerendpoint

import rt "github.com/sagernet/sing-box/common/l3router"

func (e *Endpoint) applyRoute(r rt.Route, countControl bool) error {
	if err := ValidateRoute(r); err != nil {
		if countControl {
			e.controlErrors.Add(1)
		}
		return err
	}
	e.sessMu.Lock()
	if e.peerUser == nil {
		e.peerUser = make(map[rt.RouteID]string)
	}
	if e.userPeers == nil {
		e.userPeers = make(map[string]map[rt.RouteID]struct{})
	}
	prevUser := e.peerUser[r.PeerID]
	e.sessMu.Unlock()

	e.engine.UpsertRoute(r)
	if countControl {
		e.controlUpsertOK.Add(1)
	} else {
		e.staticLoadOK.Add(1)
	}
	e.sessMu.Lock()
	e.peerUser[r.PeerID] = r.User
	if prevUser != "" && prevUser != r.User {
		if peerSet, ok := e.userPeers[prevUser]; ok {
			delete(peerSet, r.PeerID)
			if len(peerSet) == 0 {
				delete(e.userPeers, prevUser)
			}
		}
	}
	if _, ok := e.userPeers[r.User]; !ok {
		e.userPeers[r.User] = make(map[rt.RouteID]struct{})
	}
	e.userPeers[r.User][r.PeerID] = struct{}{}
	if sk, ok := e.activeUserSession[r.User]; ok {
		e.sessionIngressPeer[sk] = rt.PeerID(r.PeerID)
		e.peerEgressSession[rt.PeerID(r.PeerID)] = sk
	}
	if prevUser != "" && prevUser != r.User {
		if prevSk, ok := e.activeUserSession[prevUser]; ok {
			delete(e.peerEgressSession, rt.PeerID(r.PeerID))
			if ingress, ok := e.sessionIngressPeer[prevSk]; ok && ingress == rt.PeerID(r.PeerID) {
				delete(e.sessionIngressPeer, prevSk)
			}
		}
	}
	e.publishBindingSnapshotLocked()
	e.sessMu.Unlock()
	return nil
}

// LoadStaticRoute registers one peer from endpoint JSON bootstrap.
func (e *Endpoint) LoadStaticRoute(r rt.Route) error {
	return e.applyRoute(r, false)
}

// UpsertRoute updates/creates one peer in runtime control-plane and immediately binds
// currently active user session (if present) as ingress+egress session.
func (e *Endpoint) UpsertRoute(r rt.Route) error {
	return e.applyRoute(r, true)
}

// RemoveRoute deletes one peer in runtime control-plane.
func (e *Endpoint) RemoveRoute(id rt.RouteID) {
	if id == 0 {
		e.controlErrors.Add(1)
		return
	}
	e.engine.RemoveRoute(id)
	e.controlRemoveOK.Add(1)
	e.sessMu.Lock()
	user := e.peerUser[id]
	delete(e.peerUser, id)
	delete(e.peerEgressSession, rt.PeerID(id))
	if user != "" {
		if peerSet, ok := e.userPeers[user]; ok {
			delete(peerSet, id)
			if len(peerSet) == 0 {
				delete(e.userPeers, user)
			}
		}
		if sk, ok := e.activeUserSession[user]; ok {
			if ingress, ok := e.sessionIngressPeer[sk]; ok && ingress == rt.PeerID(id) {
				delete(e.sessionIngressPeer, sk)
			}
		}
	}
	e.publishBindingSnapshotLocked()
	e.sessMu.Unlock()
}

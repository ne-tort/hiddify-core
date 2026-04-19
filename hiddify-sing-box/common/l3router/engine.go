package l3router

import (
	"net/netip"
	"sync"
	"sync/atomic"
)

var _ Engine = (*MemEngine)(nil)
var _ RouteStore = (*MemEngine)(nil)

type MemEngine struct {
	mu sync.Mutex

	state        atomic.Pointer[memEngineState]
	packetFilter atomic.Bool
}

type memEngineState struct {
	routes        map[RouteID]compiledRoute
	ingressPolicy map[PeerID]ingressPolicyContext
	ingressExists map[PeerID]struct{}
	lookup        allowedIPTable
}

type ingressPolicyContext struct {
	filterSrcMatcher  prefixMatcher
	filterDstMatcher  prefixMatcher
	filterDstHasRules bool
}

type compiledRoute struct {
	Route
	filterSrcMatcher prefixMatcher
	filterDstMatcher prefixMatcher
}

func NewMemEngine() *MemEngine {
	e := &MemEngine{}
	e.state.Store(&memEngineState{
		routes:        make(map[RouteID]compiledRoute),
		ingressPolicy: make(map[PeerID]ingressPolicyContext),
	})
	e.packetFilter.Store(true)
	return e
}

func (e *MemEngine) SetPacketFilter(enabled bool) { e.packetFilter.Store(enabled) }

func (e *MemEngine) SetLookupBackend(backend string) error {
	switch backend {
	case "", "wg_allowedips":
		return nil
	default:
		return unsupportedLookupBackendError(backend)
	}
}

func (e *MemEngine) UpsertRoute(r Route) {
	e.mu.Lock()
	defer e.mu.Unlock()
	prev := e.state.Load()
	next := prev.clone()
	next.routes[r.PeerID] = cloneRoute(r)
	next.rebuildIndexes()
	next.rebuildIngressPolicies()
	e.state.Store(next)
}

func (e *MemEngine) RemoveRoute(id RouteID) {
	e.mu.Lock()
	defer e.mu.Unlock()
	prev := e.state.Load()
	next := prev.clone()
	delete(next.routes, id)
	next.rebuildIndexes()
	next.rebuildIngressPolicies()
	e.state.Store(next)
}

func (e *MemEngine) HandleIngressPeer(packet []byte, ingress PeerID) Decision {
	state := e.state.Load()
	if len(packet) < 1 {
		return Decision{Action: ActionDrop, DropReason: DropMalformedPacket}
	}
	if !state.hasIngressPeer(ingress) {
		return Decision{Action: ActionDrop, DropReason: DropNoIngressRoute}
	}
	if !e.packetFilter.Load() {
		return e.handleIngressNoFilter(state, packet, ingress)
	}
	policy, ok := state.ingressPolicy[ingress]
	if !ok {
		return Decision{Action: ActionDrop, DropReason: DropNoIngressRoute}
	}
	return e.handleIngressWithFilter(state, packet, ingress, policy)
}

func (e *MemEngine) handleIngressNoFilter(state *memEngineState, packet []byte, ingress PeerID) Decision {
	switch packet[0] >> 4 {
	case 4:
		dst4, ok := packetDstV4(packet)
		if !ok {
			return Decision{Action: ActionDrop, DropReason: DropMalformedPacket}
		}
		egressPeer, ok := state.lookup.lookupV4(dst4)
		if !ok || egressPeer == ingress {
			return Decision{Action: ActionDrop, DropReason: DropNoEgressRoute}
		}
		return Decision{Action: ActionForward, EgressPeerID: egressPeer}
	case 6:
		dstHi, dstLo, ok := packetDstV6HiLo(packet)
		if !ok {
			return Decision{Action: ActionDrop, DropReason: DropMalformedPacket}
		}
		egressPeer, ok := state.lookup.lookupV6(dstHi, dstLo)
		if !ok || egressPeer == ingress {
			return Decision{Action: ActionDrop, DropReason: DropNoEgressRoute}
		}
		return Decision{Action: ActionForward, EgressPeerID: egressPeer}
	default:
		return Decision{Action: ActionDrop, DropReason: DropMalformedPacket}
	}
}

func (e *MemEngine) handleIngressWithFilter(state *memEngineState, packet []byte, ingress PeerID, policy ingressPolicyContext) Decision {
	switch packet[0] >> 4 {
	case 4:
		src4, dst4, ok := packetSrcDstV4(packet)
		if !ok {
			return Decision{Action: ActionDrop, DropReason: DropMalformedPacket}
		}
		if !policy.filterSrcMatcher.containsV4(src4) {
			return Decision{Action: ActionDrop, DropReason: DropFilterSource}
		}
		if policy.filterDstHasRules && !policy.filterDstMatcher.containsV4(dst4) {
			return Decision{Action: ActionDrop, DropReason: DropFilterDestination}
		}
		egressPeer, ok := state.lookup.lookupV4(dst4)
		if !ok || egressPeer == ingress {
			return Decision{Action: ActionDrop, DropReason: DropNoEgressRoute}
		}
		return Decision{Action: ActionForward, EgressPeerID: egressPeer}
	case 6:
		srcHi, srcLo, dstHi, dstLo, ok := packetSrcDstV6HiLo(packet)
		if !ok {
			return Decision{Action: ActionDrop, DropReason: DropMalformedPacket}
		}
		if !policy.filterSrcMatcher.containsV6(srcHi, srcLo) {
			return Decision{Action: ActionDrop, DropReason: DropFilterSource}
		}
		if policy.filterDstHasRules && !policy.filterDstMatcher.containsV6(dstHi, dstLo) {
			return Decision{Action: ActionDrop, DropReason: DropFilterDestination}
		}
		egressPeer, ok := state.lookup.lookupV6(dstHi, dstLo)
		if !ok || egressPeer == ingress {
			return Decision{Action: ActionDrop, DropReason: DropNoEgressRoute}
		}
		return Decision{Action: ActionForward, EgressPeerID: egressPeer}
	default:
		return Decision{Action: ActionDrop, DropReason: DropMalformedPacket}
	}
}

func (s *memEngineState) clone() *memEngineState {
	next := &memEngineState{
		routes:        make(map[RouteID]compiledRoute, len(s.routes)),
		ingressPolicy: make(map[PeerID]ingressPolicyContext, len(s.ingressPolicy)),
		ingressExists: make(map[PeerID]struct{}, len(s.ingressExists)),
		lookup:        s.lookup,
	}
	for id, r := range s.routes {
		next.routes[id] = r
	}
	for peer, policy := range s.ingressPolicy {
		next.ingressPolicy[peer] = policy
	}
	for peer := range s.ingressExists {
		next.ingressExists[peer] = struct{}{}
	}
	return next
}

func cloneRoute(r Route) compiledRoute {
	filterSrc := normalizePrefixesExact(r.FilterSourceIPs)
	filterDst := normalizePrefixesExact(r.FilterDestinationIPs)
	allowed := normalizePrefixesExact(r.AllowedIPs)
	cp := compiledRoute{
		Route: Route{
			PeerID:               r.PeerID,
			User:                 r.User,
			FilterSourceIPs:      filterSrc,
			FilterDestinationIPs: filterDst,
			AllowedIPs:           allowed,
		},
	}
	cp.filterSrcMatcher = newPrefixMatcher(cp.FilterSourceIPs)
	cp.filterDstMatcher = newPrefixMatcher(cp.FilterDestinationIPs)
	return cp
}

func normalizePrefixesExact(list []netip.Prefix) []netip.Prefix {
	if len(list) < 2 {
		return append([]netip.Prefix(nil), list...)
	}
	out := make([]netip.Prefix, 0, len(list))
	seen := make(map[netip.Prefix]struct{}, len(list))
	for _, p := range list {
		if !p.IsValid() {
			continue
		}
		p = p.Masked()
		if _, exists := seen[p]; exists {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// rebuildIndexes publishes AllowedIPs into the wg-like LPM table; peer for each route is PeerID(id).
func (s *memEngineState) rebuildIndexes() {
	s.lookup = allowedIPTable{}
	for id, r := range s.routes {
		for _, p := range r.AllowedIPs {
			s.lookup.insert(p, PeerID(id))
		}
	}
}

func (s *memEngineState) rebuildIngressPolicies() {
	if s.ingressPolicy == nil {
		s.ingressPolicy = make(map[PeerID]ingressPolicyContext, len(s.routes))
	} else {
		clear(s.ingressPolicy)
	}
	if s.ingressExists == nil {
		s.ingressExists = make(map[PeerID]struct{}, len(s.routes))
	} else {
		clear(s.ingressExists)
	}
	for routeID, route := range s.routes {
		peer := PeerID(routeID)
		s.ingressPolicy[peer] = ingressPolicyContext{
			filterSrcMatcher:  route.filterSrcMatcher,
			filterDstMatcher:  route.filterDstMatcher,
			filterDstHasRules: route.filterDstMatcher.hasRules(),
		}
		s.ingressExists[peer] = struct{}{}
	}
}

func (s *memEngineState) hasIngressPeer(peer PeerID) bool {
	_, exists := s.ingressExists[peer]
	return exists
}

type unsupportedLookupBackendError string

func (e unsupportedLookupBackendError) Error() string {
	return "unsupported l3router lookup backend: " + string(e)
}

// Package l3router is sing-box’s reusable L3 peer routing core (used by protocol/l3router):
// WG-like LPM FIB, optional packet filter by prefix, ingress by PeerID only — no transport/session types.
package l3router

import (
	"net/netip"
)

// SessionKey identifies an authenticated transport session at the protocol adapter layer.
// Routing core must not use it in hot path decisions.
type SessionKey string

// PeerID identifies a logical dataplane peer in WG-like routing semantics.
type PeerID uint64

// RouteID identifies a logical peer row in the control plane (same numeric space as PeerID on the wire).
//
// Invariant: RouteID must equal the PeerID the protocol layer passes to HandleIngressPeer for sessions
// bound to this peer. FIB and filter indexing use PeerID(routeID).
type RouteID uint64

// Route describes one peer for control-plane registration (policies, prefixes, sing-box user binding).
type Route struct {
	// PeerID must match the dataplane PeerID for this peer (see RouteID invariant).
	PeerID RouteID
	// User is the sing-box inbound identity string (metadata.User).
	User string
	// FilterSourceIPs limits acceptable source addresses on ingress when packet filtering is enabled.
	FilterSourceIPs []netip.Prefix
	// FilterDestinationIPs limits acceptable destinations on ingress when packet filtering is enabled (optional).
	FilterDestinationIPs []netip.Prefix
	// AllowedIPs are prefixes announced into the FIB for longest-prefix egress selection (WG AllowedIPs).
	AllowedIPs []netip.Prefix
}

// Action is the data-plane disposition for one packet.
type Action uint8

const (
	ActionDrop Action = iota
	ActionForward
)

// Decision is the outcome of processing one ingress IP datagram. Protocol details stay outside:
// only PeerID and optional egress hint are visible at this boundary.
type Decision struct {
	Action Action
	// EgressPeerID, when Action == ActionForward, selects the target peer.
	EgressPeerID PeerID
	DropReason   DropReason
}

type DropReason uint8

const (
	DropUnknown DropReason = iota
	DropMalformedPacket
	DropNoIngressRoute
	DropFilterSource
	DropFilterDestination
	DropNoEgressRoute
)

// Engine is the Router data plane: optional packet filter + FIB. Implementations must not depend on inbound protocol types.
type Engine interface {
	HandleIngressPeer(packet []byte, ingress PeerID) Decision
}

// RouteStore holds control-plane Route definitions (create/update/remove).
type RouteStore interface {
	UpsertRoute(r Route)
	RemoveRoute(id RouteID)
}

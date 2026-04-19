package option

// L3RouterPeerOptions is one WireGuard-like peer in l3router JSON config.
type L3RouterPeerOptions struct {
	PeerID uint64 `json:"peer_id"`
	// User matches inbound metadata.User (e.g. vless user name).
	User string `json:"user,omitempty"`
	// AllowedIPs are prefixes installed into the LPM FIB for this peer (WireGuard AllowedIPs semantics).
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	// FilterSourceIPs restricts acceptable source addresses on ingress when endpoint packet_filter is true.
	FilterSourceIPs []string `json:"filter_source_ips,omitempty"`
	// FilterDestinationIPs restricts acceptable destination addresses when endpoint packet_filter is true (optional).
	FilterDestinationIPs []string `json:"filter_destination_ips,omitempty"`
}

// L3RouterEndpointOptions configures the L3 Router endpoint data-plane and static peers.
type L3RouterEndpointOptions struct {
	// Peers are registered into MemEngine at startup (static bootstrap path).
	Peers []L3RouterPeerOptions `json:"peers,omitempty"`
	// OverlayDestination is the UDP destination used when writing forwarded raw IP packets to a peer session
	// (must match what clients use for the IP-in-UDP tunnel, e.g. 198.18.0.1:33333).
	OverlayDestination string `json:"overlay_destination,omitempty"`
	// PacketFilter enables filter_source_ips / filter_destination_ips in the dataplane (default false).
	PacketFilter bool `json:"packet_filter,omitempty"`
	// FragmentPolicy controls IPv4 fragment handling: allow|drop.
	FragmentPolicy string `json:"fragment_policy,omitempty"`
	// OverflowPolicy controls egress queue overflow behavior: drop_new|drop_oldest.
	OverflowPolicy string `json:"overflow_policy,omitempty"`
	// TelemetryLevel controls per-packet metric overhead: off|minimal|default|forensic.
	TelemetryLevel string `json:"telemetry_level,omitempty"`
	// LookupBackend selects routing lookup backend: wg_allowedips.
	LookupBackend string `json:"lookup_backend,omitempty"`
	// EgressQueueCapPerSession is a hard cap for buffered packets per egress session.
	EgressQueueCapPerSession int `json:"egress_queue_cap_per_session,omitempty"`
	// EgressGlobalQueueBudget limits total buffered packets across all sessions.
	EgressGlobalQueueBudget int `json:"egress_global_queue_budget,omitempty"`
	// EgressWorkerCount limits concurrent egress writers.
	EgressWorkerCount int `json:"egress_worker_count,omitempty"`
	// EgressBatchSize sets max packets per scheduler dispatch.
	EgressBatchSize int `json:"egress_batch_size,omitempty"`
	// AQMTargetMS is target queue delay for latency-aware dropping.
	AQMTargetMS int `json:"aqm_target_ms,omitempty"`
	// AQMIntervalMS is the standing delay interval before AQM starts dropping.
	AQMIntervalMS int `json:"aqm_interval_ms,omitempty"`
}

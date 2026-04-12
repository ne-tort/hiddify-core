// Package awg registers the AmneziaWG endpoint. The protocol adapter matches wireguard (ICMP,
// OutboundWithPreferredRoutes, detour vs listen_port, DisplayType). JSON uses the same peer field
// names as WireGuard (e.g. pre_shared_key). Engine and IPC differ; see transport/awg.

package awg

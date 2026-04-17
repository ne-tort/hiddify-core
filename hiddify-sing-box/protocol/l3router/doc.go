// Package l3routerendpoint implements the sing-box endpoint for L3 peer routing
// (constant.TypeL3Router), alongside other endpoints such as wireguard or tailscale.
// The dataplane engine lives in common/l3router and sees only PeerID + raw IP packets.
//
// # Transport identity boundary (isolation)
//
// Mapping from an authenticated inbound session to PeerID happens only in this package:
//
//   1. Inbound sets adapter.InboundContext.User (sing-box convention for the client id —
//      vless/hy2/tuic/any UDP inbound that defines users all populate this the same way).
//   2. NewPacketConnectionEx converts User to common/l3router.SessionKey and calls enterSession.
//   3. session_state binds SessionKey to PeerID using static Route.user == string(User) and Route.peer_id.
//
// There are no references to vless, hysteria, or other protocol packages here or in common/l3router.
// Merging into vanilla sing-box means adding common/l3router, this protocol package, option types,
// include registration, and build tag — without editing protocol/vless or protocol/hysteria.
//
// # Session registration timing (hub)
//
// The hub cannot call NewPacketConnectionEx until the client has sent the first mux/VLESS UDP
// framing for that overlay stream. protocol/tun primes the overlay PacketConn after ListenPacket
// so the hub registers the l3router session before user LAN traffic (no manual “warmup”).

package l3routerendpoint

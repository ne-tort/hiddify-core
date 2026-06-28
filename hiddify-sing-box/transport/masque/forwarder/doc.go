// Package forwarder terminates IPv4/IPv6 TCP and UDP inside CONNECT-IP into host dials (S2 path).
//
// # SRP layout (IP-SOLID-03)
//
// packetForwarder is the session-scoped façade; file split (W-IP-2 IP-2-PR0) owns:
//
//   - tcp_forwarder.go — read loop, dispatchReadPacket, handleReadPacket
//   - tcp_forwarder_write.go — writeCh/downloadCh loops, sendPacketNow retry
//   - tcp_forwarder_ack.go — writeCh ACK coalescing (coalesceQueuedAckOnly)
//   - tcp_forwarder_syn.go — SYN handling, session table, shutdown
//   - tcp_session.go — per-flow TCP state + pumpRemoteToClient
//   - packet_tcp.go — segment builders, queue depth constants
//   - udp_forwarder.go / packet_udp.go — UDP termination
//   - peersnat.go / policy.go — target policy + NAT rewrite
//
// Struct-level split deferred: hot path shares session map + queue writers on one forwarder.
package forwarder

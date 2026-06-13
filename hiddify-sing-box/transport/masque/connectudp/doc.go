// Package connectudp implements CONNECT-UDP client/server dataplane helpers:
// datagram split/MTU, RFC 9297 HTTP Datagram parsing, HTTP/2 capsule relay I/O,
// ListenPacket hop/fallback orchestration (phase F), and CONNECT-UDP ICMP feedback errors.
//
// # Test layout (L4 gap-pass 5a)
//
//   - connectudp/*_test.go — unit/regression: ServeH2 relay, H2PacketConn dial/read,
//     DatagramSplitConn, ParseHTTPDatagramUDP, pace interval helpers.
//   - connectudp/h2_integration_test.go — DialH2Overlay echo/ICMP/TUN-order in-proc (3 tests).
//   - transport/masque/h2_connect_udp_proxy_test.go — masque harness proxy (ListenPacket/localize).
//   - transport/masque/h2/write_all_test.go — h2.WriteAll partial-write contract.
//   - transport/masque/transport_test.go — ensureH2UDPTransport DisableCompression + reuse.
//   - transport/masque/connect_udp_harness_test.go — H3 production ListenPacket harness.
//   - transport/masque/connect_udp_h2_harness_test.go — H2 ListenPacket harness (parity H3).
//   - transport/masque/connect_udp_*localize_test.go — perf localize benches (H3 + H2 mirror).
package connectudp

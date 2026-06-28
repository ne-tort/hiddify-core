// Package netstack hosts CONNECT-IP gVisor TCP factory, egress drain, prefix helpers, and pools (W-IP-1).
//
// # SRP layout (IP-SOLID-02)
//
// Netstack is an intentional façade over gVisor + packet-session egress; physical separation is by file:
//
//   - stack.go — gVisor stack init, inbound inject, DialContext, Close/FailWithError lifecycle
//   - egress.go — WriteNotify drain, WritePacket retry/backpressure classification
//   - factory.go — session bootstrap (NewNetstackForSession)
//   - prefix.go / prefix_listener.go — ADDRESS_ASSIGN wait helpers (cold path)
//   - outbound_headroom.go — RFC9297 datagram headroom + pool slice tagging
//   - session.go — PacketSession interfaces consumed by stack/egress
//   - hooks.go — root connectip error/obs/MTU hooks (import-cycle break)
//
// Further struct split deferred: connect-ip-go upstream keeps stack+egress on one handle.
package netstack

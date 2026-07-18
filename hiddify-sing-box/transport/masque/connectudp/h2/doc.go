// Package h2 implements CONNECT-UDP over HTTP/2 Extended CONNECT with RFC 9297 DATAGRAM capsules.
//
// Client: PacketConn dial via DialH2Overlay (one Extended CONNECT / flow — RFC 9298).
// Server: ServeH2 capsule relay (Immediate S2C + Direct uplink).
// Imports connectudp/frame and connectudp/split only — not parent connectudp.
package h2

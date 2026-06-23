// Package h2 implements CONNECT-UDP over HTTP/2 Extended CONNECT with RFC 9297 DATAGRAM capsules (M8).
//
// Client: PacketConn dial via DialH2Overlay. Server: ServeH2 capsule relay scan.
// Imports connectudp/frame and connectudp/split only — not parent connectudp.
package h2

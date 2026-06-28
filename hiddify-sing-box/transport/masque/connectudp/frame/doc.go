// Package frame implements CONNECT-UDP wire helpers (RFC 9297/9298 M0–M1):
// ParseRequest, HTTP Datagram UDP payload parsing, H2 :protocol matching,
// and RFC 9297 §4.2 request-stream capsule skip (unknown types silent discard).
package frame

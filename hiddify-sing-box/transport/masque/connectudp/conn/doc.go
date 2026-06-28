// Package conn implements the H3 CONNECT-UDP client dataplane (proxiedConn + optional C2S/S2C opts).
//
// R1 coupling (UDP-STRUCT-17): third_party/masque-go/client.go imports this package for
// H3Conn wiring. Prod dial path is connectudp/client.DialH3Production → masque-go Client.DialAddr
// → conn types here. Long-term: invert hook (masque-go accepts net.Conn factory) to drop the import.
package conn

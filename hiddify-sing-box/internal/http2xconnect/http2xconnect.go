//go:build with_masque

// Package http2xconnect is blank-imported from protocol/masque and transport/masque so it
// initializes before golang.org/x/net/http2. Extended CONNECT (RFC 8441) is enabled at
// compile time in the patched x/net fork (masque_extended_connect.go).
package http2xconnect

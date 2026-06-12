package connectip

import (
	"context"

	cip "github.com/quic-go/connect-ip-go"
)

// SameHopDialHost wires production CONNECT-IP same-hop dial from package masque (phase 16 bridge).
// Caller must hold session mutex when host methods require it.
type SameHopDialHost interface {
	DialAttempt(ctx context.Context, useHTTP2 bool) (*cip.Conn, error)
	TryHTTPFallbackSwitch(err error) bool
	CurrentOverlayH2() bool
	ResetIPH3Transport()
	ResetH2UDPTransport()
}

// DialOnCurrentHop runs the same-hop CONNECT-IP sequence: initial dial, optional http_layer
// fallback pivot, H3 client churn when on overlay h3, H2 transport churn when on overlay h2.
func DialOnCurrentHop(ctx context.Context, host SameHopDialHost, useHTTP2 bool) (*cip.Conn, error) {
	conn, err := host.DialAttempt(ctx, useHTTP2)
	if err != nil && host.TryHTTPFallbackSwitch(err) {
		useHTTP2 = host.CurrentOverlayH2()
		conn, err = host.DialAttempt(ctx, useHTTP2)
	}
	if err != nil && !useHTTP2 {
		host.ResetIPH3Transport()
		conn, err = host.DialAttempt(ctx, false)
		if err != nil && host.TryHTTPFallbackSwitch(err) {
			useHTTP2 = host.CurrentOverlayH2()
			conn, err = host.DialAttempt(ctx, useHTTP2)
		}
	}
	if err != nil && useHTTP2 {
		host.ResetH2UDPTransport()
		conn, err = host.DialAttempt(ctx, true)
		if err != nil && host.TryHTTPFallbackSwitch(err) {
			useHTTP2 = host.CurrentOverlayH2()
			conn, err = host.DialAttempt(ctx, useHTTP2)
		}
	}
	return conn, err
}

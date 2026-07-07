package stream

import (
	"context"
	"time"
)

// ConnectStreamHandshakeTimeout is the CONNECT RoundTrip budget when sing-box passes
// no dial deadline (or a shorter one). One constant, one boundary — see dialTCPStream.
const ConnectStreamHandshakeTimeout = 30 * time.Second

// ConnectStreamHandshakeContext scopes one CONNECT-stream dial (single RoundTrip chain).
//
// Sing-box dial ctx may cancel early (DNS cascade, parallel dial). Handshake uses
// context.WithoutCancel so parent cancel does not abort an in-flight CONNECT; only
// an explicit deadline bounds the attempt.
func ConnectStreamHandshakeContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		return context.WithTimeout(context.Background(), ConnectStreamHandshakeTimeout)
	}
	base := context.WithoutCancel(parent)
	if deadline, ok := parent.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > ConnectStreamHandshakeTimeout {
			return context.WithDeadline(base, deadline)
		}
	}
	return context.WithTimeout(base, ConnectStreamHandshakeTimeout)
}

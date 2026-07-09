package stream

import (
	"context"
	"time"
)

// ConnectStreamHandshakeTimeout is the CONNECT RoundTrip budget when sing-box passes
// no dial deadline (or a shorter one). Field WAN OpenStreamSync can block under parallel
// TUN burst until peer raises MAX_STREAMS. Bounds handshake only — not relay lifetime.
const ConnectStreamHandshakeTimeout = 60 * time.Second

// ConnectStreamHandshakeContext scopes one CONNECT-stream dial (single RoundTrip chain).
//
// H2O / connect-ip-go parity: context.WithoutCancel(parent) so DNS cascade / parallel
// dial cancel does not abort an in-flight CONNECT; only an explicit deadline bounds it.
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

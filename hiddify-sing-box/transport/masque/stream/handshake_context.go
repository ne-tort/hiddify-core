package stream

import (
	"context"
	"time"
)

// ConnectStreamHandshakeTimeout is the CONNECT RoundTrip budget when sing-box passes
// no dial deadline (or a shorter one). One constant, one boundary — see dialTCPStream.
const ConnectStreamHandshakeTimeout = 30 * time.Second

// ConnectStreamQueueContext scopes semaphore waits (in-flight / stream budget) before RoundTrip.
//
// Queue wait must not share the sing-box dial deadline (often 30s on :443) or RoundTrip
// timeout. context.WithoutCancel(parent) still inherits Deadline(), which caused field
// browser bursts to fail as "connect roundtrip: context canceled" after queue pile-up.
func ConnectStreamQueueContext(parent context.Context) (context.Context, context.CancelFunc) {
	_ = parent
	return context.WithCancel(context.Background())
}

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

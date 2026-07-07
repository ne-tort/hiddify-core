package session

import "context"

// connectStreamMaxInFlight limits concurrent CONNECT-stream RoundTrips per QUIC session.
//
// quic-go http3 uses OpenStreamSync(ctx): when peer bidi budget is exhausted, each extra
// dial blocks inside RoundTrip until ctx expires (30s pile-up). This semaphore is
// backpressure — not retry — it queues excess dials instead of N× OpenStreamSync wait.
const connectStreamMaxInFlight = 32

// ConnectStreamInFlight bounds parallel CONNECT handshakes on one shared TCPHTTP session.
type ConnectStreamInFlight struct {
	slots chan struct{}
}

// NewConnectStreamInFlight builds an in-flight limiter with n slots.
func NewConnectStreamInFlight(n int) *ConnectStreamInFlight {
	if n <= 0 {
		n = connectStreamMaxInFlight
	}
	return &ConnectStreamInFlight{slots: make(chan struct{}, n)}
}

// Acquire waits for a slot or returns when ctx is done.
func (l *ConnectStreamInFlight) Acquire(ctx context.Context) error {
	if l == nil || l.slots == nil {
		return nil
	}
	select {
	case l.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

// Release returns a slot from Acquire.
func (l *ConnectStreamInFlight) Release() {
	if l == nil || l.slots == nil {
		return
	}
	select {
	case <-l.slots:
	default:
	}
}

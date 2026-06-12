package connectip

import (
	"context"
	"errors"
	"net"
	"time"
)

// IsRetryableError reports whether a CONNECT-IP overlay fault may benefit from same-hop retry/backoff.
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return false
}

// WaitContextBackoff sleeps for d unless ctx is canceled first.
func WaitContextBackoff(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timer.C:
		return nil
	}
}

package stream

import (
	"context"
	"testing"
)

func TestConnectStreamRoundTripShouldNotRetryBudgetExpiry(t *testing.T) {
	t.Parallel()
	if connectStreamRoundTripShouldRetry(context.DeadlineExceeded) {
		t.Fatal("handshake budget expiry is not a transport fault — no retry")
	}
	if connectStreamRoundTripShouldRetry(context.Canceled) {
		t.Fatal("explicit cancel must not retry")
	}
}

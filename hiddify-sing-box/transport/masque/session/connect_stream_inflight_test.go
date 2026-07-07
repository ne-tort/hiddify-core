package session

import (
	"context"
	"testing"
	"time"
)

func TestConnectStreamInFlightQueuesExcess(t *testing.T) {
	t.Parallel()
	l := NewConnectStreamInFlight(1)
	ctx := context.Background()
	if err := l.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := l.Acquire(waitCtx); err == nil {
		t.Fatal("second acquire must wait until ctx expires")
	}
	l.Release()
	if err := l.Acquire(ctx); err != nil {
		t.Fatalf("released slot must be reusable: %v", err)
	}
	l.Release()
}

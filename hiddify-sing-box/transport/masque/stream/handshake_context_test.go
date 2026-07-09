package stream

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestConnectStreamHandshakeUsesDefaultWhenParentShort(t *testing.T) {
	t.Parallel()
	parent, parentCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer parentCancel()
	ctx, cancel := ConnectStreamHandshakeContext(parent)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected handshake deadline")
	}
	if time.Until(deadline) < 25*time.Second {
		t.Fatalf("short parent must not cap handshake; got %v remaining", time.Until(deadline))
	}
}

func TestConnectStreamHandshakeUsesLongParentDeadline(t *testing.T) {
	t.Parallel()
	parent, parentCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer parentCancel()
	ctx, cancel := ConnectStreamHandshakeContext(parent)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected handshake deadline")
	}
	if time.Until(deadline) > 91*time.Second || time.Until(deadline) < 89*time.Second {
		t.Fatalf("long parent deadline should inherit; got %v remaining", time.Until(deadline))
	}
}

func TestConnectStreamHandshakeExtendsShorterParentToHandshakeBudget(t *testing.T) {
	t.Parallel()
	parent, parentCancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer parentCancel()
	ctx, cancel := ConnectStreamHandshakeContext(parent)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected handshake deadline")
	}
	rem := time.Until(deadline)
	if rem < 59*time.Second || rem > 61*time.Second {
		t.Fatalf("parent below handshake budget must get ConnectStreamHandshakeTimeout; got %v remaining", rem)
	}
}

func TestGATEConnectStreamHandshakeIgnoresParentCancel(t *testing.T) {
	t.Parallel()
	parent, parentCancel := context.WithCancel(context.Background())
	ctx, cancel := ConnectStreamHandshakeContext(parent)
	defer cancel()
	parentCancel()
	select {
	case <-ctx.Done():
		t.Fatal("handshake ctx must not follow parent cancel (WithoutCancel boundary)")
	default:
	}
	cancel()
	select {
	case <-ctx.Done():
	default:
		t.Fatal("handshake ctx must cancel when its own cancel runs")
	}
}

func TestGATEConnectStreamHandshakeAlreadyCanceledParentStillDials(t *testing.T) {
	t.Parallel()
	parent, parentCancel := context.WithCancel(context.Background())
	parentCancel()
	ctx, cancel := ConnectStreamHandshakeContext(parent)
	defer cancel()
	if err := ctx.Err(); err != nil {
		t.Fatalf("already-canceled parent must not poison handshake ctx: %v", err)
	}
	cancel()
	if err := ctx.Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("handshake cancel: %v", err)
	}
}

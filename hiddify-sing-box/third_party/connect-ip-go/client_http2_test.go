package connectip

import (
	"context"
	"testing"
	"time"
)

func TestH2ExtendedConnectRequestContextCancelsBeforeDetach(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	reqCtx, stop := NewH2ExtendedConnectRequestContext(parent)
	t.Cleanup(func() { stop(false) })

	cancelParent()
	select {
	case <-reqCtx.Done():
	case <-time.After(200 * time.Millisecond):
		t.Fatal("request context was not canceled by parent cancellation")
	}
}

func TestH2ExtendedConnectRequestContextDetachesAfterHandshake(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	reqCtx, stop := NewH2ExtendedConnectRequestContext(parent)
	stop(true)

	cancelParent()
	select {
	case <-reqCtx.Done():
		t.Fatal("request context canceled after detach")
	case <-time.After(50 * time.Millisecond):
	}

	stop(false)
}

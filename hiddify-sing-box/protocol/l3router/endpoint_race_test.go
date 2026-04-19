package l3routerendpoint

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	rt "github.com/sagernet/sing-box/common/l3router"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/buf"
)

func TestEndpointConcurrentRouteAndSessionChurn(t *testing.T) {
	loggerFactory := log.NewNOPFactory()
	endpointAny, err := NewEndpoint(context.Background(), nil, loggerFactory.Logger(), "race-l3", option.L3RouterEndpointOptions{})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	e := endpointAny.(*Endpoint)
	route := rt.Route{
		PeerID:          9,
		User:            "owner-a",
		FilterSourceIPs: mustPrefixes(t, "10.0.0.0/24"),
		AllowedIPs:      mustPrefixes(t, "10.9.0.0/24"),
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = e.UpsertRoute(route)
				e.RemoveRoute(route.PeerID)
			}
		}()
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				e.enterSession("owner-a")
				e.leaveSession("owner-a")
			}
		}()
	}
	wg.Wait()
}

// Egress to a SessionKey that has never entered (no userRef) must not spawn idle workers or queues.
func TestEgressPhantomSessionUsesFastPath(t *testing.T) {
	loggerFactory := log.NewNOPFactory()
	endpointAny, err := NewEndpoint(context.Background(), nil, loggerFactory.Logger(), "queue", option.L3RouterEndpointOptions{})
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	e := endpointAny.(*Endpoint)
	for i := 0; i < 400; i++ {
		b := buf.As([]byte{0x45, 0x00, 0x00, 0x14})
		queued, queueFull := e.enqueueEgress("missing-session", b)
		if queued || queueFull {
			b.Release()
			t.Fatalf("expected fast-path reject, got queued=%v queueFull=%v", queued, queueFull)
		}
		b.Release()
	}
	if depth := e.SnapshotMetrics().QueueDepth; depth != 0 {
		t.Fatalf("expected zero queue depth for phantom session, got %d", depth)
	}
	if e.queueOverflow.Load() != 0 {
		t.Fatalf("queueOverflow should be 0, got %d", e.queueOverflow.Load())
	}
}

func mustPrefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	result, err := ParsePrefixes(values)
	if err != nil {
		t.Fatalf("ParsePrefixes: %v", err)
	}
	return result
}

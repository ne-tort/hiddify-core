package l3routerendpoint

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	rt "github.com/sagernet/sing-box/common/l3router"
)

func TestRoutedPacketConnectionEarlyBindDoesNotLeakUserRef(t *testing.T) {
	ep := newEndpointForSurfaceTest(t)
	metadata := adapter.InboundContext{User: "owner-a"}

	_ = ep.RoutedPacketConnection(context.Background(), nil, metadata, nil, ep)

	ep.refMu.Lock()
	ref := ep.userRef[rt.SessionKey("owner-a")]
	ep.refMu.Unlock()
	if ref != 0 {
		t.Fatalf("early bind via tracker must not increment userRef, got %d", ref)
	}
	if _, ok := ep.ingressPeerForSession(rt.SessionKey("owner-a")); ok {
		// no peers by default in this helper endpoint, so ingress mapping must stay empty
		t.Fatal("unexpected ingress mapping without configured peer")
	}
}

package l3routerendpoint

import (
	"testing"

	rt "github.com/sagernet/sing-box/common/l3router"
	"github.com/sagernet/sing/common/buf"
)

func TestLeaveSessionIgnoresStaleGeneration(t *testing.T) {
	ep := newEndpointForSurfaceTest(t)
	ep.enterSession("owner-a")
	ep.refMu.Lock()
	ep.sessionGeneration["owner-a"] = 7
	ep.refMu.Unlock()

	ep.leaveSessionWithGeneration("owner-a", 6)

	ep.refMu.Lock()
	_, hasGen := ep.sessionGeneration["owner-a"]
	ep.refMu.Unlock()
	if !hasGen {
		t.Fatal("stale close must not remove current generation")
	}
	if _, ok := ep.activeUserSession["owner-a"]; !ok {
		t.Fatal("stale close must not unbind active user session")
	}
}

func TestPendingQueueFlushOnSessionReady(t *testing.T) {
	ep := newEndpointForSurfaceTest(t)
	ep.enterSession("owner-b")
	ep.sessMu.Lock()
	ep.peerEgressSession[rt.PeerID(2)] = "owner-b"
	ep.publishBindingSnapshotLocked()
	ep.sessMu.Unlock()

	payload := buf.As([]byte{0x45, 0x00, 0x00, 0x14})
	if !ep.queuePendingForPeer(rt.PeerID(2), payload) {
		t.Fatal("expected pending queue accept")
	}
	ep.flushPendingForSession("owner-b")
	if depth := ep.SnapshotMetrics().QueueDepth; depth == 0 {
		t.Fatal("expected pending packet to move into scheduler queue")
	}
}

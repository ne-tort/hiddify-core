package connectip

import (
	"context"
	"net/netip"
	"testing"
)

func TestConnectIPOutboundQueueDepthAlwaysZero(t *testing.T) {
	clientSession, _ := newPacketPipePair()
	stack, err := NewNetstack(context.Background(), clientSession, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	defer stack.Close()
	if got := stack.OutboundQueueDepth(); got != 0 {
		t.Fatalf("OutboundQueueDepth=%d want 0 (sync egress)", got)
	}
}

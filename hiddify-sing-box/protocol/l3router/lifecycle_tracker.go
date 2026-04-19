package l3routerendpoint

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

// InterfaceUpdated implements adapter.InterfaceUpdateListener.
// Fail-safe behavior for long-lived SMB-like flows: reset volatile egress/session state
// so stale writers and packet conns are forced to re-establish lazily.
func (e *Endpoint) InterfaceUpdated() {
	e.addNetworkResets(1)
	e.logger.WarnContext(context.Background(), "[l3router] network update detected; resetting volatile session/egress state")
	if e.scheduler != nil {
		e.scheduler.reset(true)
	} else {
		var conns []N.PacketConn
		e.sessMu.Lock()
		conns = make([]N.PacketConn, 0, len(e.sessions))
		for sk, c := range e.sessions {
			conns = append(conns, c)
			delete(e.sessions, sk)
		}
		e.sessMu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	}
}

func (e *Endpoint) RoutedConnection(ctx context.Context, conn net.Conn, _ adapter.InboundContext, _ adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	if !isL3RouterMatch(e, matchOutbound) {
		return conn
	}
	return conn
}

func (e *Endpoint) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, _ adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	if !isL3RouterMatch(e, matchOutbound) {
		return conn
	}
	_ = metadata // tracker hook is intentionally observation-only; readiness is post-register.
	return conn
}

func isL3RouterMatch(e *Endpoint, matchOutbound adapter.Outbound) bool {
	if matchOutbound == nil {
		return false
	}
	if matchOutbound.Type() != e.Type() {
		return false
	}
	return matchOutbound.Tag() == e.Tag()
}

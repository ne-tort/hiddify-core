package connectip

import (
	"context"

	cipnet "github.com/sagernet/sing-box/transport/masque/connectip/netstack"
)

// TCPNetstackFactory constructs a CONNECT-IP TCP netstack for a packet session.
type TCPNetstackFactory interface {
	New(ctx context.Context, session PacketSession, bootstrap SessionBootstrap) (TCPNetstack, error)
}

// DefaultTCPNetstackFactory is the production CONNECT-IP TCP netstack factory.
var DefaultTCPNetstackFactory TCPNetstackFactory = tcpNetstackFactory{}

type tcpNetstackFactory struct{}

// NewProductionTCPNetstack builds the live CONNECT-IP TCP netstack with optional egress hooks.
func NewProductionTCPNetstack(ctx context.Context, session PacketSession, boot SessionBootstrap, hooks NetstackOptions) (TCPNetstack, error) {
	return cipnet.NewFromBootstrap(ctx, wrapPacketSession(session), sessionBootstrapToNetstack(boot), hooks)
}

func (f tcpNetstackFactory) New(ctx context.Context, session PacketSession, boot SessionBootstrap) (TCPNetstack, error) {
	return NewProductionTCPNetstack(ctx, session, boot, NetstackOptions{})
}

// NewProductionTCPNetstackFromPacketSession builds the live TCP netstack with bootstrap
// from session and egress batch flush when session is a ClientPacketSession.
func NewProductionTCPNetstackFromPacketSession(ctx context.Context, session PacketSession) (TCPNetstack, error) {
	hooks := NetstackOptions{}
	if cps, ok := session.(*ClientPacketSession); ok {
		hooks.OnEgressBatchComplete = cps.FlushEgressBatch
	}
	return NewProductionTCPNetstack(ctx, session, SessionBootstrapFrom(session), hooks)
}

func sessionBootstrapToNetstack(b SessionBootstrap) cipnet.Bootstrap {
	boot := cipnet.Bootstrap{
		ProfileLocalIPv4:   b.ProfileLocalIPv4,
		ProfileLocalIPv6:   b.ProfileLocalIPv6,
		DatagramCeiling:    b.DatagramCeiling,
		OverlayH2:          b.OverlayH2,
		TCPDatagramSlack:   b.TCPDatagramSlack,
		DatagramCeilingMax: b.DatagramCeilingMax,
	}
	if b.PrefixSource != nil {
		boot.PrefixSource = prefixSourceBridge{src: b.PrefixSource}
	}
	return boot
}

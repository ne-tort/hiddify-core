package masque

import (
	"github.com/sagernet/sing-box/transport/masque/session"
	"context"

	cip "github.com/sagernet/sing-box/transport/masque/connectip"
)

func init() {
	cip.SetErrors(cip.Errors{
		StackInit:      session.ErrTCPStackInit,
		Dial:           session.ErrTCPDial,
		Closed:         session.ErrLifecycleClosed,
		DialRequiresIP: session.ErrTCPOverConnectIP,
		Transport:      session.ErrTransportInit,
		Capability:     session.ErrCapability,
	})
	cip.SetObs(cip.CounterObsHooks())
}

type (
	connectIPTCPNetstack        = cip.Netstack
	connectIPTCPNetstackOptions = cip.NetstackOptions
	TCPNetstack                 = cip.TCPNetstack
)

// TCPNetstackFactory builds a CONNECT-IP userspace TCP stack for a packet session.
type TCPNetstackFactory interface {
	New(ctx context.Context, session IPPacketSession) (TCPNetstack, error)
}

// DefaultTCPNetstackFactory constructs CONNECT-IP TCP netstacks for masque sessions.
var DefaultTCPNetstackFactory TCPNetstackFactory = masqueTCPNetstackFactory{}

type masqueTCPNetstackFactory struct{}

func (masqueTCPNetstackFactory) New(ctx context.Context, session IPPacketSession) (TCPNetstack, error) {
	return cip.DefaultTCPNetstackFactory.New(ctx, session, sessionBootstrapFrom(session))
}

func sessionBootstrapFrom(session IPPacketSession) cip.SessionBootstrap {
	return cip.SessionBootstrapFrom(session)
}

func newConnectIPTCPNetstack(ctx context.Context, session IPPacketSession, opts connectIPTCPNetstackOptions) (*connectIPTCPNetstack, error) {
	if opts.OnEgressBatchComplete == nil {
		type egressFlusher interface {
			ScheduleEgressFlush()
		}
		if flusher, ok := session.(egressFlusher); ok {
			opts.OnEgressBatchComplete = flusher.ScheduleEgressFlush
		}
	}
	return cip.NewNetstack(ctx, session, cip.NetstackOptions(opts))
}

func isRetryablePacketReadError(err error) bool {
	return cip.IsRetryablePacketReadError(err)
}

func isBenignConnectIPEgressTeardownError(err error) bool {
	return cip.IsBenignEgressTeardownError(err)
}

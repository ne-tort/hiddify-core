package stream

import (
	"context"
	"errors"
	"net"

	M "github.com/sagernet/sing/common/metadata"
)

// DialHopChainHost wires production CONNECT-stream hop-chain dial from package masque (phase B3 bridge).
type DialHopChainHost interface {
	DialAttempt(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	TryHTTPFallbackSwitch(err error) bool
	HTTPLayerAutoEnabled() bool
	IsAuthFailure(err error) bool
	ClearHTTPFallbackAfterGiveUp()
	RebuildOverlayTransport()
	PreAdvanceHop()
	AdvanceHopLocked() (advanced bool, resetErr error)
}

// DialWithHopChain runs CONNECT-stream dial with http_layer fallback pivot and hopOrder advance.
func DialWithHopChain(ctx context.Context, host DialHopChainHost, destination M.Socksaddr) (net.Conn, error) {
	var lastErr error
	for {
		conn, err := host.DialAttempt(ctx, destination)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if !TCPConnectStreamErrMayBenefitFromNextHop(lastErr) {
			host.ClearHTTPFallbackAfterGiveUp()
			return nil, lastErr
		}

		if lastErr != nil && host.TryHTTPFallbackSwitch(lastErr) {
			conn2, err2 := host.DialAttempt(ctx, destination)
			if err2 == nil {
				return conn2, nil
			}
			lastErr = err2
			if !TCPConnectStreamErrMayBenefitFromNextHop(lastErr) {
				host.ClearHTTPFallbackAfterGiveUp()
				return nil, lastErr
			}
		}

		if authFail := host.IsAuthFailure(lastErr); authFail {
			host.ClearHTTPFallbackAfterGiveUp()
			return nil, lastErr
		}

		if ctx.Err() != nil {
			host.ClearHTTPFallbackAfterGiveUp()
			return nil, errors.Join(lastErr, context.Cause(ctx))
		}

		host.PreAdvanceHop()

		advanced, resetErr := host.AdvanceHopLocked()
		if !advanced {
			host.ClearHTTPFallbackAfterGiveUp()
			if ctx.Err() != nil {
				if resetErr != nil {
					return nil, errors.Join(resetErr, context.Cause(ctx))
				}
				return nil, errors.Join(lastErr, context.Cause(ctx))
			}
			if resetErr != nil {
				return nil, resetErr
			}
			return nil, lastErr
		}
		if resetErr != nil {
			host.ClearHTTPFallbackAfterGiveUp()
			if ctx.Err() != nil {
				return nil, errors.Join(resetErr, context.Cause(ctx))
			}
			return nil, resetErr
		}
	}
}

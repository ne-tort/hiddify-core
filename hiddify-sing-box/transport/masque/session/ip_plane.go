package session

import (
	"context"

	connectip "github.com/quic-go/connect-ip-go"
)

// IPPlaneHost wires production CONNECT-IP open from package masque (phase F bridge).
type IPPlaneHost interface {
	BeginOpenIPSession()
	ClearHTTPFallbackAfterGiveUp()
	RecordOpenNotSupported() error

	CtxDone(ctx context.Context) error
	JoinCtxCancel(err error, ctx context.Context) error

	CurrentOverlayH2() bool
	DialConnectIPOnCurrentHopLocked(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error)
	ReuseIPConnIfPresent(overlayH2 bool) (IPPacketSession, bool)
	OnDialSuccess(conn *connectip.Conn, useHTTP2 bool, startIngress bool) IPPacketSession

	AdvanceHop() bool
	ResetHopTemplates() error

	RecordOpenFailure(err error)
	LogDialFailure(err error)
}

// OpenIPSessionLocked opens or reuses the CONNECT-IP packet plane. Caller must hold s.Mu.
func OpenIPSessionLocked(s *CoreSession, host IPPlaneHost, ctx context.Context) (IPPacketSession, error) {
	host.BeginOpenIPSession()
	if !s.Caps.ConnectIP {
		err := host.RecordOpenNotSupported()
		host.ClearHTTPFallbackAfterGiveUp()
		return nil, err
	}
	if ctxErr := host.CtxDone(ctx); ctxErr != nil {
		host.RecordOpenFailure(ctxErr)
		host.ClearHTTPFallbackAfterGiveUp()
		return nil, ctxErr
	}
	if sess, ok := host.ReuseIPConnIfPresent(host.CurrentOverlayH2()); ok {
		return sess, nil
	}
	useHTTP2 := host.CurrentOverlayH2()
	conn, err := host.DialConnectIPOnCurrentHopLocked(ctx, useHTTP2)
	if err != nil {
		host.LogDialFailure(err)
		if ctxErr := host.CtxDone(ctx); ctxErr != nil {
			host.RecordOpenFailure(ctxErr)
			host.ClearHTTPFallbackAfterGiveUp()
			return nil, ctxErr
		}
		for host.AdvanceHop() {
			if resetErr := host.ResetHopTemplates(); resetErr != nil {
				host.ClearHTTPFallbackAfterGiveUp()
				return nil, host.JoinCtxCancel(resetErr, ctx)
			}
			useHTTP2 = host.CurrentOverlayH2()
			conn, err = host.DialConnectIPOnCurrentHopLocked(ctx, useHTTP2)
			if err == nil {
				return host.OnDialSuccess(conn, useHTTP2, false), nil
			}
			host.LogDialFailure(err)
			if ctxErr := host.CtxDone(ctx); ctxErr != nil {
				host.RecordOpenFailure(err)
				host.ClearHTTPFallbackAfterGiveUp()
				return nil, host.JoinCtxCancel(err, ctx)
			}
		}
		host.RecordOpenFailure(err)
		host.ClearHTTPFallbackAfterGiveUp()
		return nil, host.JoinCtxCancel(err, ctx)
	}
	return host.OnDialSuccess(conn, useHTTP2, true), nil
}

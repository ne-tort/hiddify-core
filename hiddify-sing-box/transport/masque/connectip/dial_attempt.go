package connectip

import (
	"context"

	cip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
)

// AttemptDialHost wires production CONNECT-IP per-attempt dial from package masque (phase 18 bridge).
type AttemptDialHost interface {
	Hook() func(ctx context.Context, useHTTP2 bool) (*cip.Conn, error)
	OnSuccess(useHTTP2 bool)
	OnCtxCanceled()
	DialH2(ctx context.Context) (*cip.Conn, error)
	HasTemplateIP() bool
	ErrNoTemplateIP() error
	LogH3Attempt(dialAddr string)
	OpenH3ClientConn(ctx context.Context) (*http3.ClientConn, error)
	DialH3WithBootstrap(ctx context.Context, clientConn *http3.ClientConn) (*cip.Conn, error)
	OverlayDialAddr() string
}

// DialAttempt performs one CONNECT-IP dial on the current overlay (H2 capsules vs H3 datagram tunnel).
func DialAttempt(ctx context.Context, host AttemptDialHost, useHTTP2 bool) (*cip.Conn, error) {
	if hook := host.Hook(); hook != nil {
		conn, err := hook(ctx, useHTTP2)
		if err == nil && conn != nil {
			host.OnSuccess(useHTTP2)
		}
		return conn, err
	}
	if useHTTP2 {
		select {
		case <-ctx.Done():
			host.OnCtxCanceled()
			return nil, context.Cause(ctx)
		default:
		}
		conn, err := host.DialH2(ctx)
		if err != nil || conn == nil {
			return conn, err
		}
		host.OnSuccess(true)
		return conn, nil
	}
	select {
	case <-ctx.Done():
		host.OnCtxCanceled()
		return nil, context.Cause(ctx)
	default:
	}
	if !host.HasTemplateIP() {
		return nil, host.ErrNoTemplateIP()
	}
	dialAddr := host.OverlayDialAddr()
	host.LogH3Attempt(dialAddr)
	clientConn, err := host.OpenH3ClientConn(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := host.DialH3WithBootstrap(ctx, clientConn)
	if err != nil {
		return nil, err
	}
	host.OnSuccess(false)
	return conn, nil
}

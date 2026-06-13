package connectip

import (
	"context"
	"net/http"

	cip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// FinishSessionDial runs post-dial bootstrap after CONNECT-IP tunnel open succeeds.
func FinishSessionDial(conn BootstrapConn, bootstrap SessionBootstrapParams) error {
	return FinishSessionDialWithContext(context.Background(), conn, bootstrap)
}

// FinishSessionDialWithContext runs bootstrap on dpCtx after tunnel open. Callers should pass
// DataplaneContext(openCtx) so a canceled open ctx does not abort ADDRESS_ASSIGN bootstrap.
func FinishSessionDialWithContext(dpCtx context.Context, conn BootstrapConn, bootstrap SessionBootstrapParams) error {
	if conn == nil {
		return nil
	}
	return RunPostDialBootstrap(dpCtx, conn, bootstrap)
}

// DialH2TunnelWithBootstrap opens CONNECT-IP over HTTP/2 and runs session bootstrap.
func DialH2TunnelWithBootstrap(ctx context.Context, rt http.RoundTripper, template *uritemplate.Template, dial H2DialParams, bootstrap SessionBootstrapParams) (*cip.Conn, error) {
	conn, _, err := DialH2Tunnel(ctx, rt, template, dial)
	if err != nil || conn == nil {
		return conn, err
	}
	if err := FinishSessionDialWithContext(DataplaneContext(ctx), conn, bootstrap); err != nil {
		return nil, err
	}
	return conn, nil
}

// DialH3TunnelWithBootstrap opens CONNECT-IP over HTTP/3 and runs session bootstrap.
func DialH3TunnelWithBootstrap(ctx context.Context, clientConn *http3.ClientConn, template *uritemplate.Template, dial H3DialParams, bootstrap SessionBootstrapParams) (*cip.Conn, error) {
	conn, _, err := DialH3Tunnel(ctx, clientConn, template, dial)
	if err != nil || conn == nil {
		return conn, err
	}
	if err := FinishSessionDialWithContext(DataplaneContext(ctx), conn, bootstrap); err != nil {
		return nil, err
	}
	return conn, nil
}

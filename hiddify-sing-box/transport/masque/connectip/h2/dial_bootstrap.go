package h2

import (
	"context"
	"net/http"

	cip "github.com/quic-go/connect-ip-go"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/yosida95/uritemplate/v3"
)

// DialH2TunnelWithBootstrap opens CONNECT-IP over HTTP/2 and runs session bootstrap.
func DialH2TunnelWithBootstrap(ctx context.Context, rt http.RoundTripper, template *uritemplate.Template, dial mcip.H2DialParams, bootstrap mcip.SessionBootstrapParams) (*cip.Conn, error) {
	conn, _, err := DialH2Tunnel(ctx, rt, template, dial)
	if err != nil || conn == nil {
		return conn, err
	}
	if err := mcip.FinishSessionDialWithContext(mcip.DataplaneContext(ctx), conn, bootstrap); err != nil {
		return nil, err
	}
	return conn, nil
}

package stream

import (
	"context"
	"net"
	"net/http"
)

// H3TunnelFromResponse builds the CONNECT-stream tunnel after a successful H3 CONNECT.
// tunnel is supplied by transport/masque (delegates to h3.ConnectTunnelFromResponse).
func H3TunnelFromResponse(
	ctx context.Context,
	resp *http.Response,
	targetHost string,
	targetPort uint16,
	tunnel func(context.Context, *http.Response, string, uint16) (net.Conn, error),
) (net.Conn, error) {
	inner, err := tunnel(ctx, resp, targetHost, targetPort)
	if err != nil {
		TraceTCPf("masque tcp connect_stream h3 tunnel err host=%s port=%d err=%v",
			targetHost, targetPort, err)
		return nil, err
	}
	return NewTunnelConn(inner), nil
}

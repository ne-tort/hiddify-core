package stream

import (
	"context"
	"io"
	"net"
	"net/http"
)

// H3TunnelFromResponse builds the CONNECT-stream tunnel after a successful H3 CONNECT.
// tunnel is supplied by transport/masque (delegates to h3.ConnectTunnelFromResponse).
func H3TunnelFromResponse(
	ctx context.Context,
	resp *http.Response,
	upload io.WriteCloser,
	targetHost string,
	targetPort uint16,
	allowPipe bool,
	tunnel func(context.Context, *http.Response, io.WriteCloser, string, uint16, bool) (net.Conn, error),
) (net.Conn, error) {
	conn, err := tunnel(ctx, resp, upload, targetHost, targetPort, allowPipe)
	if err != nil {
		TraceTCPf("masque tcp connect_stream h3 tunnel err host=%s port=%d allow_pipe=%t err=%v",
			targetHost, targetPort, allowPipe, err)
		return nil, err
	}
	return conn, nil
}

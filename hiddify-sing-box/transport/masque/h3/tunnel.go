package h3

import (
	"context"
	"errors"
	"net"
	"net/http"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// ConnectTunnelFromResponse builds the standard MASQUE H3 TCP tunnel after CONNECT succeeds.
func ConnectTunnelFromResponse(ctx context.Context, resp *http.Response, targetHost string, targetPort uint16) (net.Conn, error) {
	conn, err := TunnelConnFromCONNECT(ctx, resp, targetHost, targetPort)
	if err != nil {
		return nil, errors.Join(strm.Errs.TCPConnectStreamFailed, err)
	}
	return strm.NewTunnelConn(conn), nil
}

// ConnectRequest builds an RFC 9114 CONNECT request (nil Body = tunneled upload on the bidi stream).
// setAuth may be nil when no MASQUE authorization header is required.
func ConnectRequest(ctx context.Context, url string, serverHost string, setAuth func(http.Header)) (*http.Request, error) {
	// nil Body, not http.NoBody: quic-go doRequest treats NoBody as a real body, reads EOF,
	// and closes the CONNECT stream send half before tunneled TCP upload (write on closed stream).
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, url, nil)
	if err != nil {
		return nil, err
	}
	req.Host = serverHost
	req.Proto = "HTTP/3"
	req.ProtoMajor = 3
	req.Header = make(http.Header)
	if setAuth != nil {
		setAuth(req.Header)
	}
	return req, nil
}

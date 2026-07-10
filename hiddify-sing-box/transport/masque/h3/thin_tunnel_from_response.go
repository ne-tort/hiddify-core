package h3

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"

	"github.com/quic-go/quic-go/http3"
)

func thinTunnelConnFromConnectResponse(ctx context.Context, resp *http.Response, targetHost string, targetPort uint16) (*ThinTunnelConn, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.Join(ErrTunnelConnFailed, errors.New("nil CONNECT response"))
	}
	remoteAddr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort))))
	hs, ok := resp.Body.(http3.HTTPStreamer)
	if !ok {
		return nil, ErrHTTPStreamerMissing
	}
	str := hs.HTTPStream()
	if str == nil {
		return nil, errors.Join(ErrTunnelConnFailed, errors.New("HTTPStreamer returned nil stream"))
	}
	if rel, ok := resp.Body.(http3.ResponseStreamReleaser); ok {
		rel.ReleaseHTTPStream()
	}
	http3.EnableMasqueConnectStream(str)
	conn := NewThinTunnelConn(ThinTunnelConnParams{
		H3Stream: str,
		Ctx:      ctx,
		Local:    &net.TCPAddr{},
		Remote:   remoteAddr,
	})
	primeH3ConnectStream(str)
	return conn, nil
}

// ThinTunnelConnFromCONNECT maps a completed HTTP/3 CONNECT RoundTrip to a thin tunneled net.Conn.
func ThinTunnelConnFromCONNECT(ctx context.Context, resp *http.Response, targetHost string, targetPort uint16) (*ThinTunnelConn, error) {
	conn, err := thinTunnelConnFromConnectResponse(ctx, resp, targetHost, targetPort)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, errors.Join(ErrTunnelConnFailed, err)
	}
	return conn, nil
}

package h3

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"

	"github.com/quic-go/quic-go/http3"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// ErrHTTPStreamerMissing is returned when the CONNECT response cannot expose *http3.Stream.
var ErrHTTPStreamerMissing = errors.New("h3: response body is not http3.HTTPStreamer (need quic-go-patched)")

func tunnelConnFromConnectResponse(ctx context.Context, resp *http.Response, targetHost string, targetPort uint16) (*TunnelConn, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.Join(ErrTunnelConnFailed, errors.New("nil CONNECT response"))
	}
	remoteAddr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort))))
	streamCtx := context.WithoutCancel(ctx)
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
	params := TunnelConnParams{
		H3Stream:         str,
		Ctx:              streamCtx,
		Local:            &net.TCPAddr{},
		Remote:           remoteAddr,
		RouteBidiDuplex:  strm.ConnectStreamRouteBidiDuplex(ctx),
		ConnectStreamLeg: strm.ConnectStreamLegFromContext(ctx),
	}
	applyTunnelConnParamsHook(&params)
	conn := NewTunnelConn(params)
	_ = PrimeH3UploadBootstrapOnConn(conn)
	return conn, nil
}

// TunnelConnFromCONNECT maps a completed HTTP/3 CONNECT RoundTrip to a tunneled net.Conn.
func TunnelConnFromCONNECT(ctx context.Context, resp *http.Response, targetHost string, targetPort uint16) (*TunnelConn, error) {
	conn, err := tunnelConnFromConnectResponse(ctx, resp, targetHost, targetPort)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, errors.Join(ErrTunnelConnFailed, err)
	}
	return conn, nil
}

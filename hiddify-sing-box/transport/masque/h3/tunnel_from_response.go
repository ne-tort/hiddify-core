package h3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"

	"github.com/quic-go/quic-go/http3"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// ErrHTTPStreamerMissing is returned when the CONNECT response cannot expose *http3.Stream.
var ErrHTTPStreamerMissing = errors.New("h3: response body is not http3.HTTPStreamer (need quic-go-patched)")

var errHTTPStreamerMissing = ErrHTTPStreamerMissing

func tunnelConnFromConnectResponse(ctx context.Context, resp *http.Response, reqBody io.WriteCloser, targetHost string, targetPort uint16) (*TunnelConn, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.Join(ErrTunnelConnFailed, errors.New("nil CONNECT response"))
	}
	remoteAddr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort))))
	streamCtx := context.WithoutCancel(ctx)
	if hs, ok := resp.Body.(http3.HTTPStreamer); ok {
		str := hs.HTTPStream()
		if str == nil {
			return nil, errors.Join(ErrTunnelConnFailed, errors.New("HTTPStreamer returned nil stream"))
		}
		if rel, ok := resp.Body.(http3.ResponseStreamReleaser); ok {
			rel.ReleaseHTTPStream()
		}
		params := TunnelConnParams{
			H3Stream:         str,
			Ctx:              streamCtx,
			Local:            &net.TCPAddr{},
			Remote:           remoteAddr,
			RouteBidiDuplex:  strm.ConnectStreamRouteBidiDuplex(ctx),
			ConnectStreamLeg: strm.ConnectStreamLegFromContext(ctx),
		}
		if ConnectTunnelUsesPipeUpload(reqBody) {
			params.H3Stream = nil
			params.Reader = str
			params.Writer = reqBody
		}
		applyTunnelConnParamsHook(&params)
		return NewTunnelConn(params), nil
	}
	return nil, errHTTPStreamerMissing
}

func tunnelConnFromPipeFallback(ctx context.Context, resp *http.Response, reqBody io.WriteCloser, targetHost string, targetPort uint16) (*TunnelConn, error) {
	remoteAddr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort))))
	streamCtx := context.WithoutCancel(ctx)
	params := TunnelConnParams{
		Reader: resp.Body,
		Writer: reqBody,
		Ctx:    streamCtx,
		Local:  &net.TCPAddr{},
		Remote: remoteAddr,
	}
	applyTunnelConnParamsHook(&params)
	return NewTunnelConn(params), nil
}

func dialTunnelConnFromResponse(ctx context.Context, resp *http.Response, reqBody io.WriteCloser, targetHost string, targetPort uint16, allowPipeFallback bool) (*TunnelConn, string, error) {
	conn, err := tunnelConnFromConnectResponse(ctx, resp, reqBody, targetHost, targetPort)
	if err == nil {
		if ConnectTunnelUsesPipeUpload(reqBody) {
			return conn, "h3_pipe_up", nil
		}
		return conn, "h3_stream", nil
	}
	if !allowPipeFallback || !errors.Is(err, errHTTPStreamerMissing) {
		if reqBody != nil {
			_ = reqBody.Close()
		}
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, "", errors.Join(ErrTunnelConnFailed, err)
	}
	if reqBody == nil {
		return nil, "", errors.Join(ErrTunnelConnFailed, fmt.Errorf("pipe fallback requires request body writer: %w", err))
	}
	conn, ferr := tunnelConnFromPipeFallback(ctx, resp, reqBody, targetHost, targetPort)
	return conn, "pipe", ferr
}

// TunnelConnFromCONNECT maps a completed HTTP/3 CONNECT RoundTrip to a tunneled net.Conn.
// allowPipeFallback is for unit tests without patched quic-go only.
func TunnelConnFromCONNECT(ctx context.Context, resp *http.Response, reqBody io.WriteCloser, targetHost string, targetPort uint16, allowPipeFallback bool) (net.Conn, string, error) {
	conn, mode, err := dialTunnelConnFromResponse(ctx, resp, reqBody, targetHost, targetPort, allowPipeFallback)
	if err != nil {
		return nil, "", err
	}
	return conn, mode, nil
}

// ConnFromMASQUECONNECT is deprecated; use TunnelConnFromCONNECT.
func ConnFromMASQUECONNECT(ctx context.Context, resp *http.Response, reqBody io.WriteCloser, targetHost string, targetPort uint16, allowPipeFallback bool) (net.Conn, string, error) {
	return TunnelConnFromCONNECT(ctx, resp, reqBody, targetHost, targetPort, allowPipeFallback)
}

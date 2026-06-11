package connectauthority

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go/http3"
)

// ErrHTTPStreamerMissing is returned when the CONNECT response cannot expose *http3.Stream.
var ErrHTTPStreamerMissing = errors.New("connectauthority: response body is not http3.HTTPStreamer (need quic-go-patched)")

var errHTTPStreamerMissing = ErrHTTPStreamerMissing

// masqueConnectUseH3Stream is true when upload/download use one *http3.Stream (default).
// Pipe upload is opt-in: MASQUE_CONNECT_STREAM_PIPE_UPLOAD=1 or MASQUE_CONNECT_AUTHORITY_PIPE_UPLOAD=1.
func masqueConnectUseH3Stream() bool {
	for _, key := range []string{
		"MASQUE_CONNECT_STREAM_PIPE_UPLOAD",
		"MASQUE_CONNECT_AUTHORITY_PIPE_UPLOAD",
	} {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
		case "1", "true", "yes", "on", "pipe":
			return false
		}
	}
	// Legacy opt-out names (deprecated).
	if raw := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_STREAM_H3_STREAM")); raw != "" {
		return raw != "0"
	}
	if raw := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_AUTHORITY_H3_STREAM")); raw != "" {
		return raw != "0"
	}
	return true
}

// connFromConnectResponse exposes the tunneled *http3.Stream from a successful CONNECT response.
func connFromConnectResponse(ctx context.Context, resp *http.Response, reqBody io.WriteCloser, targetHost string, targetPort uint16) (*Conn, error) {
	if resp == nil || resp.Body == nil {
		return nil, errors.Join(ErrConnectAuthorityFailed, errors.New("nil CONNECT response"))
	}
	remoteAddr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort))))
	streamCtx := context.WithoutCancel(ctx)
	if hs, ok := resp.Body.(http3.HTTPStreamer); ok {
		str := hs.HTTPStream()
		if str == nil {
			return nil, errors.Join(ErrConnectAuthorityFailed, errors.New("HTTPStreamer returned nil stream"))
		}
		if rel, ok := resp.Body.(http3.ResponseStreamReleaser); ok {
			rel.ReleaseHTTPStream()
		}
		params := ConnParams{
			H3Stream: str,
			Ctx:      streamCtx,
			Local:    &net.TCPAddr{},
			Remote:   remoteAddr,
		}
		if reqBody != nil && !masqueConnectUseH3Stream() {
			params.H3Stream = nil
			params.Reader = str
			params.Writer = reqBody
		}
		return NewConn(params), nil
	}
	return nil, errHTTPStreamerMissing
}

// connFromPipeFallback is the legacy shim (response body + request pipe) for tests without patched quic-go.
func connFromPipeFallback(ctx context.Context, resp *http.Response, reqBody io.WriteCloser, targetHost string, targetPort uint16) (*Conn, error) {
	remoteAddr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort))))
	streamCtx := context.WithoutCancel(ctx)
	return NewConn(ConnParams{
		Reader: resp.Body,
		Writer: reqBody,
		Ctx:    streamCtx,
		Local:  &net.TCPAddr{},
		Remote: remoteAddr,
	}), nil
}

func dialConnFromResponse(ctx context.Context, resp *http.Response, reqBody io.WriteCloser, targetHost string, targetPort uint16, allowPipeFallback bool) (*Conn, string, error) {
	conn, err := connFromConnectResponse(ctx, resp, reqBody, targetHost, targetPort)
	if err == nil {
		if reqBody != nil && !masqueConnectUseH3Stream() {
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
		return nil, "", errors.Join(ErrConnectAuthorityFailed, err)
	}
	if reqBody == nil {
		return nil, "", errors.Join(ErrConnectAuthorityFailed, fmt.Errorf("pipe fallback requires request body writer: %w", err))
	}
	conn, ferr := connFromPipeFallback(ctx, resp, reqBody, targetHost, targetPort)
	return conn, "pipe", ferr
}

// TunnelConnFromCONNECT maps a completed HTTP/3 CONNECT RoundTrip to a tunneled net.Conn.
// allowPipeFallback is for unit tests without patched quic-go only.
func TunnelConnFromCONNECT(ctx context.Context, resp *http.Response, reqBody io.WriteCloser, targetHost string, targetPort uint16, allowPipeFallback bool) (net.Conn, string, error) {
	conn, mode, err := dialConnFromResponse(ctx, resp, reqBody, targetHost, targetPort, allowPipeFallback)
	if err != nil {
		return nil, "", err
	}
	return conn, mode, nil
}

// ConnFromMASQUECONNECT is deprecated; use TunnelConnFromCONNECT.
func ConnFromMASQUECONNECT(ctx context.Context, resp *http.Response, reqBody io.WriteCloser, targetHost string, targetPort uint16, allowPipeFallback bool) (net.Conn, string, error) {
	return TunnelConnFromCONNECT(ctx, resp, reqBody, targetHost, targetPort, allowPipeFallback)
}

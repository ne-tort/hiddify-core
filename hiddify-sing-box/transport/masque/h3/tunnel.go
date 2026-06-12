package h3

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// ConnectUsePipeUpload selects the legacy request-body pipe for tunneled upload.
// Default is one *http3.Stream for both directions (RFC 9114 CONNECT tunnel).
func ConnectUsePipeUpload() bool {
	for _, key := range []string{
		"MASQUE_CONNECT_STREAM_PIPE_UPLOAD",
		"MASQUE_CONNECT_AUTHORITY_PIPE_UPLOAD",
	} {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
		case "1", "true", "yes", "on", "pipe":
			return true
		}
	}
	// Legacy opt-out names (deprecated).
	for _, key := range []string{
		"MASQUE_CONNECT_STREAM_H3_STREAM",
		"MASQUE_CONNECT_AUTHORITY_H3_STREAM",
	} {
		if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
			return raw == "0"
		}
	}
	return false
}

// ConnectTunnelFromResponse builds the standard MASQUE H3 TCP tunnel after CONNECT succeeds.
func ConnectTunnelFromResponse(ctx context.Context, resp *http.Response, upload io.WriteCloser, targetHost string, targetPort uint16, allowPipe bool) (net.Conn, error) {
	conn, _, err := TunnelConnFromCONNECT(ctx, resp, upload, targetHost, targetPort, allowPipe)
	if err != nil {
		return nil, errors.Join(strm.Errs.TCPConnectStreamFailed, err)
	}
	return strm.NewTunnelConn(conn), nil
}

// ConnectRequest builds an RFC 9114 CONNECT request (nil Body = tunneled upload on the bidi stream).
// setAuth may be nil when no MASQUE authorization header is required.
func ConnectRequest(ctx context.Context, url string, serverHost string, usePipe bool, setAuth func(http.Header)) (*http.Request, *io.PipeReader, io.WriteCloser, error) {
	if usePipe {
		pr, pw := io.Pipe()
		req, err := http.NewRequestWithContext(ctx, http.MethodConnect, url, pr)
		if err != nil {
			_ = pw.Close()
			_ = pr.Close()
			return nil, nil, nil, err
		}
		req.Host = serverHost
		req.ContentLength = -1
		req.Proto = "HTTP/3"
		req.ProtoMajor = 3
		req.Header = make(http.Header)
		if setAuth != nil {
			setAuth(req.Header)
		}
		return req, pr, pw, nil
	}
	// nil Body, not http.NoBody: quic-go doRequest treats NoBody as a real body, reads EOF,
	// and closes the CONNECT stream send half before tunneled TCP upload (write on closed stream).
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, url, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	req.Host = serverHost
	req.Proto = "HTTP/3"
	req.ProtoMajor = 3
	req.Header = make(http.Header)
	if setAuth != nil {
		setAuth(req.Header)
	}
	return req, nil, nil, nil
}

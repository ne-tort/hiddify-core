package masque

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/sagernet/sing-box/transport/masque/connectauthority"
)

// masqueConnectUsePipeUpload selects the legacy request-body pipe for tunneled upload.
// Default is one *http3.Stream for both directions (RFC 9114 CONNECT tunnel).
func masqueConnectUsePipeUpload() bool {
	for _, key := range []string{
		"MASQUE_CONNECT_STREAM_PIPE_UPLOAD",
		"MASQUE_CONNECT_AUTHORITY_PIPE_UPLOAD",
	} {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
		case "1", "true", "yes", "on", "pipe":
			return true
		}
	}
	return false
}

// h3ConnectTunnelFromResponse builds the standard MASQUE H3 TCP tunnel after CONNECT succeeds.
func h3ConnectTunnelFromResponse(ctx context.Context, resp *http.Response, upload io.WriteCloser, targetHost string, targetPort uint16) (net.Conn, error) {
	allowPipe := masqueConnectUsePipeUpload()
	conn, _, err := connectauthority.TunnelConnFromCONNECT(ctx, resp, upload, targetHost, targetPort, allowPipe)
	if err != nil {
		tcpTracef("masque tcp connect_stream h3 tunnel err host=%s port=%d allow_pipe=%t err=%v", targetHost, targetPort, allowPipe, err)
		return nil, errors.Join(ErrTCPConnectStreamFailed, err)
	}
	return &connectStreamTunnelConn{inner: conn}, nil
}

// h3ConnectRequest builds an RFC 9114 CONNECT request (NoBody = tunneled stream upload by default).
func h3ConnectRequest(ctx context.Context, url string, serverHost string, options ClientOptions, usePipe bool) (*http.Request, *io.PipeReader, io.WriteCloser, error) {
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
		setMasqueAuthorizationHeader(req.Header, options)
		return req, pr, pw, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, url, http.NoBody)
	if err != nil {
		return nil, nil, nil, err
	}
	req.Host = serverHost
	req.Proto = "HTTP/3"
	req.ProtoMajor = 3
	req.Header = make(http.Header)
	setMasqueAuthorizationHeader(req.Header, options)
	return req, nil, nil, nil
}

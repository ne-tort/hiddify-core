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

func connectEnvPipeUpload(keys ...string) bool {
	for _, key := range keys {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
		case "1", "true", "yes", "on", "pipe":
			return true
		case "0", "false", "no", "off", "bidi", "stream":
			return false
		}
	}
	return false
}

func connectEnvPipeUploadExplicit(keys ...string) (bool, bool) {
	for _, key := range keys {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			continue
		}
		switch strings.ToLower(raw) {
		case "1", "true", "yes", "on", "pipe":
			return true, true
		case "0", "false", "no", "off", "bidi", "stream":
			return false, true
		}
	}
	return false, false
}

func connectEnvLegacyH3StreamOptOut(keys ...string) bool {
	for _, key := range keys {
		if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
			return raw == "0"
		}
	}
	return false
}

// ConnectStreamUseDualConnect selects P2 dual CONNECT-stream (separate download + upload tunnels).
// Prod default on (H3 duplex escape); opt-out MASQUE_CONNECT_STREAM_DUAL_CONNECT=0.
func ConnectStreamUseDualConnect() bool {
	on, explicit := connectEnvPipeUploadExplicit("MASQUE_CONNECT_STREAM_DUAL_CONNECT")
	if explicit {
		return on
	}
	return true
}

// ConnectStreamDualLegParallelQUIC dials upload leg on a separate QUIC connection (P6 escape
// for connection-level duplex aggregate ceiling). Opt-in: MASQUE_CONNECT_STREAM_DUAL_CONNECT_PARALLEL=1.
// Route duplex (MarkConnectionCopyDuplex) also enables P6 without env.
func ConnectStreamDualLegParallelQUIC() bool {
	if !ConnectStreamUseDualConnect() {
		return false
	}
	return connectEnvPipeUpload("MASQUE_CONNECT_STREAM_DUAL_CONNECT_PARALLEL")
}

// ConnectStreamThinEnabled selects Invisv-shaped CONNECT-stream dial: nil Body, HTTPStreamer → *http3.Stream,
// io.CopyBuffer WriteTo without duplex_coord. Opt-in: MASQUE_CONNECT_STREAM_THIN=1 (REF3-4).
func ConnectStreamThinEnabled() bool {
	return connectEnvPipeUpload("MASQUE_CONNECT_STREAM_THIN")
}

// ConnectStreamUsePipeUpload selects pipe upload for CONNECT-stream (template_tcp).
// Default: h3_stream (nil Body, Invisv-shaped bidi). Legacy pipe: MASQUE_CONNECT_STREAM_PIPE_UPLOAD=1
// or MASQUE_CONNECT_STREAM_H3_STREAM=0. Disabled when dual CONNECT or thin mode is on.
func ConnectStreamUsePipeUpload() bool {
	if ConnectStreamThinEnabled() || ConnectStreamUseDualConnect() {
		return false
	}
	if on, ok := connectEnvPipeUploadExplicit("MASQUE_CONNECT_STREAM_PIPE_UPLOAD"); ok {
		return on
	}
	if connectEnvLegacyH3StreamOptOut("MASQUE_CONNECT_STREAM_H3_STREAM") {
		return true
	}
	if raw := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_STREAM_H3_STREAM")); raw == "1" {
		return false
	}
	return false
}

// ConnectUsePipeUpload reports pipe mode for CONNECT-stream.
func ConnectUsePipeUpload() bool {
	return ConnectStreamUsePipeUpload()
}

// ConnectTunnelUsesPipeUpload reports whether a non-nil CONNECT request body should use pipe tunnel mode.
func ConnectTunnelUsesPipeUpload(reqBody io.WriteCloser) bool {
	if reqBody != nil {
		return true
	}
	return ConnectStreamUsePipeUpload()
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

package h2

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	cip "github.com/quic-go/connect-ip-go"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/sagernet/sing-box/transport/masque/httpx"
	"github.com/yosida95/uritemplate/v3"
)

// DialH2Tunnel opens CONNECT-IP over HTTP/2 Extended CONNECT (RFC 8441 + RFC 9297).
// Prod upload: masque/h2 tracked io.Pipe + ExtendedConnectUploadBody (sing-box dial parity).
func DialH2Tunnel(ctx context.Context, rt http.RoundTripper, template *uritemplate.Template, p mcip.H2DialParams) (*cip.Conn, *http.Response, error) {
	if rt == nil {
		return nil, nil, fmt.Errorf("masque connect-ip h2: nil round tripper")
	}
	opts := mcip.BuildH2DialOptions(p)
	if err := cip.ValidateFlowForwardingTemplate(template); err != nil {
		return nil, nil, err
	}
	if opts.HTTP2LegacyConnect {
		return cip.DialHTTP2(ctx, rt, template, opts)
	}

	rawURL, err := cip.BuildConnectIPRequestURL(template, opts)
	if err != nil {
		return nil, nil, err
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, fmt.Errorf("masque connect-ip h2: parse url: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	default:
	}

	pipeR, pipeW := h2c.NewTrackedUploadPipe()
	uploadBody := &h2c.ExtendedConnectUploadBody{Pipe: pipeR, Writer: pipeW}

	streamCtx, stopRelay := httpx.NewH2ExtendedConnectRequestContext(ctx)
	handshakeOK := false
	defer func() {
		if !handshakeOK {
			stopRelay(false)
		}
	}()

	proto := cip.ExtendedConnectProtocolName(opts)
	req, err := http.NewRequestWithContext(streamCtx, http.MethodConnect, rawURL, uploadBody)
	if err != nil {
		_ = pipeW.Close()
		_ = pipeR.Close()
		return nil, nil, fmt.Errorf("masque connect-ip h2: new request: %w", err)
	}
	cip.ApplyH2ConnectIPRequestHeaders(req, u, opts, proto)

	resp, err := rt.RoundTrip(req)
	if err != nil {
		_ = pipeW.Close()
		_ = pipeR.Close()
		return nil, nil, fmt.Errorf("masque connect-ip h2: roundtrip: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = pipeW.Close()
		_ = pipeR.Close()
		_ = resp.Body.Close()
		return nil, resp, fmt.Errorf("connect-ip: server responded with %d", resp.StatusCode)
	}
	if ctxErr := context.Cause(ctx); ctxErr != nil {
		_ = pipeW.Close()
		_ = pipeR.Close()
		_ = resp.Body.Close()
		return nil, nil, ctxErr
	}
	stopRelay(true)
	handshakeOK = true

	conn, err := cip.NewConnFromH2ExtendedConnect(resp, cip.H2ExtendedConnectLeg{
		Writer:      pipeW,
		WriterClose: pipeW,
		Reader:      pipeR,
		UploadBody:  uploadBody,
		OnClose:     func() { stopRelay(false) },
	}, opts)
	if err != nil {
		_ = pipeW.Close()
		_ = pipeR.Close()
		_ = resp.Body.Close()
		return nil, resp, err
	}
	return conn, resp, nil
}

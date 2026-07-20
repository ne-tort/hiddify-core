package connectip

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// H2ExtendedConnectLeg carries the client upload half after HTTP/2 Extended CONNECT succeeds.
// Production dialers (sing-box connectip / CONNECT-UDP) supply masque/h2 shallow pipe + ExtendedConnectUploadBody.
type H2ExtendedConnectLeg struct {
	Writer      io.Writer
	WriterClose io.Closer
	Reader      io.Closer
	UploadBody  interface {
		MarkUploadWriterDone()
	}
	OnClose func()
}

// ValidateFlowForwardingTemplate rejects templates that still expose {target}/{ipproto}.
func ValidateFlowForwardingTemplate(template *uritemplate.Template) error {
	return validateFlowForwardingTemplateVars(template)
}

// BuildConnectIPRequestURL expands the CONNECT-IP URI template for dial.
func BuildConnectIPRequestURL(template *uritemplate.Template, opts DialOptions) (string, error) {
	return buildConnectIPRequestURL(template, opts)
}

// ExtendedConnectProtocolName returns the :protocol pseudo-header for opts.
func ExtendedConnectProtocolName(opts DialOptions) string {
	proto := strings.TrimSpace(opts.ExtendedConnectProtocol)
	if proto == "" {
		return requestProtocol
	}
	return proto
}

// ApplyH2ConnectIPRequestHeaders sets RFC 8441 / CONNECT-IP headers on an Extended CONNECT request.
func ApplyH2ConnectIPRequestHeaders(req *http.Request, u *url.URL, opts DialOptions, proto string) {
	if req == nil {
		return
	}
	req.ContentLength = -1
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set(":protocol", proto)
	req.Header.Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	for k, vv := range opts.ExtraRequestHeaders {
		if len(vv) == 0 {
			continue
		}
		cp := make([]string, len(vv))
		copy(cp, vv)
		req.Header[k] = cp
	}
	if t := strings.TrimSpace(opts.BearerToken); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	if proto == "cf-connect-ip" {
		req.Header.Set("User-Agent", "")
		req.Header.Set("cf-connect-proto", "cf-connect-ip")
		req.Header.Set("pq-enabled", "false")
	}
	if u != nil && u.Host != "" {
		req.Host = u.Host
	}
}

// NewConnFromH2ExtendedConnect binds an established HTTP/2 CONNECT-IP tunnel to *Conn.
func NewConnFromH2ExtendedConnect(resp *http.Response, leg H2ExtendedConnectLeg, opts DialOptions) (*Conn, error) {
	if resp == nil || resp.Body == nil {
		return nil, fmt.Errorf("connect-ip: h2 extended connect: nil response body")
	}
	if leg.Writer == nil || leg.Reader == nil {
		return nil, fmt.Errorf("connect-ip: h2 extended connect: nil upload leg")
	}
	if err := validateResponseCapsuleProtocol(resp.Header); err != nil {
		return nil, err
	}
	str := &h2CapsulePipeStream{
		body:       resp.Body,
		pipeW:      leg.Writer,
		pipeWClose: leg.WriterClose,
		pipeR:      leg.Reader,
		uploadBody: leg.UploadBody,
		onClose:    leg.OnClose,
	}
	conn := newProxiedConn(str, true)
	applyDialInteroperability(conn, opts)
	return conn, nil
}

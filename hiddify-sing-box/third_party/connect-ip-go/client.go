package connectip

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// Dial dials a proxied connection to a target server.
func Dial(ctx context.Context, conn *http3.ClientConn, template *uritemplate.Template) (*Conn, *http.Response, error) {
	if err := validateFlowForwardingTemplateVars(template); err != nil {
		return nil, nil, err
	}
	rawURL, err := buildConnectIPRequestURL(template)
	if err != nil {
		return nil, nil, err
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to parse URI: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	case <-conn.Context().Done():
		return nil, nil, context.Cause(conn.Context())
	case <-conn.ReceivedSettings():
	}
	settings := conn.Settings()
	if !settings.EnableExtendedConnect {
		return nil, nil, errors.New("connect-ip: server didn't enable Extended CONNECT")
	}
	if !settings.EnableDatagrams {
		return nil, nil, errors.New("connect-ip: server didn't enable datagrams")
	}

	rstr, err := conn.OpenRequestStream(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to open request stream: %w", err)
	}
	if err := rstr.SendRequestHeader(&http.Request{
		Method: http.MethodConnect,
		Proto:  requestProtocol,
		Host:   u.Host,
		Header: http.Header{http3.CapsuleProtocolHeader: []string{capsuleProtocolHeaderValue}},
		URL:    u,
	}); err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to send request: %w", err)
	}
	// TODO: optimistically return the connection
	rsp, err := rstr.ReadResponse()
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to read response: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %d", rsp.StatusCode)
	}
	return newProxiedConn(rstr), rsp, nil
}

func buildConnectIPRequestURL(template *uritemplate.Template) (string, error) {
	if len(template.Varnames()) == 0 {
		return template.Raw(), nil
	}
	values := uritemplate.Values{}
	for _, variable := range template.Varnames() {
		switch variable {
		case flowVarTarget:
			// Full-flow default scope for RFC-compatible endpoints requiring {target}.
			values[flowVarTarget] = uritemplate.String("0.0.0.0/0")
		case flowVarIPProto:
			// "0" follows RFC wildcard semantics for all upper-layer protocols.
			values[flowVarIPProto] = uritemplate.String("0")
		default:
			return "", ErrFlowForwardingUnsupported
		}
	}
	expanded, err := template.Expand(values)
	if err != nil {
		return "", fmt.Errorf("connect-ip: failed to expand flow forwarding template: %w", err)
	}
	if strings.TrimSpace(expanded) == "" {
		return "", errors.New("connect-ip: empty flow forwarding request URL after template expansion")
	}
	return expanded, nil
}

package stream

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strconv"

	"github.com/quic-go/quic-go/http3"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

// DialOnceHooks wires one CONNECT-stream dial attempt (H2 extended CONNECT vs H3).
type DialOnceHooks struct {
	PathHostForTemplate func(unbracketedHost string, tcpIPv6PathBracket bool) string
	FixExpandedURL      func(expanded string, tcpIPv6PathBracket bool) string
	RewritePercentIPv6  func(u *url.URL, tcpIPv6PathBracket bool)
	DialH2              func(ctx context.Context, tcpURL *url.URL, targetHost string, destination M.Socksaddr) (net.Conn, error)
	DialH3              func(ctx context.Context, tcpURL *url.URL, targetHost string, targetPort uint16, tcpHTTP *http3.Transport) (net.Conn, error)
}

// DialOnce expands the TCP MASQUE template and dials over the selected HTTP layer.
func DialOnce(
	ctx context.Context,
	hooks DialOnceHooks,
	templateTCP *uritemplate.Template,
	destination M.Socksaddr,
	httpLayer string,
	httpLayerH2 string,
	tcpHTTP *http3.Transport,
	targetHost string,
	targetPort uint16,
	pathBracket bool,
) (net.Conn, *url.URL, error) {
	tcpPathHost := hooks.PathHostForTemplate(targetHost, pathBracket)
	expanded, err := templateTCP.Expand(uritemplate.Values{
		"target_host": uritemplate.String(tcpPathHost),
		"target_port": uritemplate.String(strconv.Itoa(int(destination.Port))),
	})
	if err != nil {
		return nil, nil, errors.Join(Errs.Capability, E.Cause(err, "expand TCP MASQUE template"))
	}
	expanded = hooks.FixExpandedURL(expanded, pathBracket)
	tcpURL, err := url.Parse(expanded)
	if err != nil {
		return nil, nil, errors.Join(Errs.Capability, E.Cause(err, "parse TCP MASQUE URL"))
	}
	hooks.RewritePercentIPv6(tcpURL, pathBracket)
	if httpLayer == httpLayerH2 {
		conn, err := hooks.DialH2(ctx, tcpURL, targetHost, destination)
		return conn, tcpURL, err
	}
	if tcpHTTP == nil {
		return nil, nil, errors.Join(Errs.Capability, E.New("internal: masque CONNECT-stream HTTP/3 transport uninitialized"))
	}
	conn, err := hooks.DialH3(ctx, tcpURL, targetHost, targetPort, tcpHTTP)
	return conn, tcpURL, err
}

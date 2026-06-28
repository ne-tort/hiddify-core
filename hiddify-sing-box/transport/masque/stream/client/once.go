package client

import (
	"context"
	"net"
	"net/url"

	"github.com/quic-go/quic-go/http3"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

// OnceTemplateWire carries masque TCP template expand helpers.
type OnceTemplateWire struct {
	PathHostForTemplate func(unbracketedHost string, tcpIPv6PathBracket bool) string
	FixExpandedURL      func(expanded string, tcpIPv6PathBracket bool) string
	RewritePercentIPv6  func(u *url.URL, tcpIPv6PathBracket bool)
}

// OnceDialFuncs wires H2/H3 leaf dials for one template expand attempt.
type OnceDialFuncs struct {
	DialH2 func(ctx context.Context, tcpURL *url.URL, targetHost string, destination M.Socksaddr) (net.Conn, error)
	DialH3 func(ctx context.Context, tcpURL *url.URL, targetHost string, targetPort uint16, tcpHTTP *http3.Transport) (net.Conn, error)
}

// NewOnceHooks builds stream.DialOnceHooks from template wire + leaf dial funcs.
func NewOnceHooks(w OnceTemplateWire, d OnceDialFuncs) strm.DialOnceHooks {
	return strm.DialOnceHooks{
		PathHostForTemplate: w.PathHostForTemplate,
		FixExpandedURL:      w.FixExpandedURL,
		RewritePercentIPv6:  w.RewritePercentIPv6,
		DialH2:              d.DialH2,
		DialH3:              d.DialH3,
	}
}

// OnceInput is one CONNECT-stream template expand + layer dial attempt.
type OnceInput struct {
	Template    *uritemplate.Template
	Destination M.Socksaddr
	HTTPLayer   string
	HTTPLayerH2 string
	TCPHTTP     *http3.Transport
	TargetHost  string
	TargetPort  uint16
	PathBracket bool
}

// DialOnce expands template_tcp and dials over H2 or H3.
func DialOnce(ctx context.Context, hooks strm.DialOnceHooks, in OnceInput) (net.Conn, *url.URL, error) {
	return strm.DialOnce(ctx, hooks, in.Template, in.Destination, in.HTTPLayer, in.HTTPLayerH2, in.TCPHTTP, in.TargetHost, in.TargetPort, in.PathBracket)
}

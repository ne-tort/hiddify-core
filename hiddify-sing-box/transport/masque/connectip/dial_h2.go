package connectip

import (
	"context"
	"net/http"
	"strings"

	cip "github.com/quic-go/connect-ip-go"
	"github.com/yosida95/uritemplate/v3"
)

// H2DialParams carries CONNECT-IP HTTP/2 dial overlay fields from the MASQUE session.
type H2DialParams struct {
	BearerToken           string
	WarpConnectIPProtocol string
	ExtraRequestHeaders   http.Header
	PathObfuscationKey    []byte
}

// BuildH2DialOptions maps overlay params to connect-ip-go DialOptions for HTTP/2 Extended CONNECT.
func BuildH2DialOptions(p H2DialParams) cip.DialOptions {
	dopts := cip.DialOptions{
		PathObfuscationKey: p.PathObfuscationKey,
	}
	if p.ExtraRequestHeaders != nil {
		dopts.ExtraRequestHeaders = p.ExtraRequestHeaders
	} else if tok := strings.TrimSpace(p.BearerToken); tok != "" {
		dopts.BearerToken = tok
	}
	proto := strings.TrimSpace(p.WarpConnectIPProtocol)
	if proto != "" {
		dopts.ExtendedConnectProtocol = proto
		if strings.EqualFold(proto, "cf-connect-ip") {
			dopts.HTTP2LegacyConnect = true
		}
	}
	return dopts
}

// DialH2Tunnel opens a CONNECT-IP session over an HTTP/2 RoundTripper.
func DialH2Tunnel(ctx context.Context, rt http.RoundTripper, template *uritemplate.Template, p H2DialParams) (*cip.Conn, *http.Response, error) {
	conn, rsp, err := cip.DialHTTP2(ctx, rt, template, BuildH2DialOptions(p))
	if err != nil || conn == nil {
		return conn, rsp, err
	}
	LogCfConnectIPHTTPResponse(rsp, p.WarpConnectIPProtocol)
	return conn, rsp, nil
}

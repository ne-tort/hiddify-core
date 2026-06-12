package connectip

import (
	"context"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"

	cip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// H3DialParams carries CONNECT-IP HTTP/3 dial overlay fields from the MASQUE session.
type H3DialParams struct {
	Tag                   string
	BearerToken           string
	WarpConnectIPProtocol string
	ExtraRequestHeaders http.Header
}

// BuildH3DialOptions maps overlay params to connect-ip-go DialOptions.
func BuildH3DialOptions(p H3DialParams) cip.DialOptions {
	proto := strings.TrimSpace(p.WarpConnectIPProtocol)
	token := strings.TrimSpace(p.BearerToken)
	if p.ExtraRequestHeaders != nil {
		dopts := cip.DialOptions{
			BearerToken:             token,
			ExtendedConnectProtocol: proto,
			ExtraRequestHeaders:     p.ExtraRequestHeaders,
		}
		if strings.EqualFold(proto, "cf-connect-ip") {
			dopts.IgnoreExtendedConnect = true
		}
		if p.ExtraRequestHeaders.Get("Authorization") != "" {
			dopts.BearerToken = ""
		}
		return dopts
	}
	if proto != "" {
		dopts := cip.DialOptions{
			BearerToken:             token,
			ExtendedConnectProtocol: proto,
		}
		if strings.EqualFold(proto, "cf-connect-ip") {
			dopts.IgnoreExtendedConnect = true
		}
		return dopts
	}
	return cip.DialOptions{BearerToken: token}
}

// DialH3Tunnel opens a CONNECT-IP session over an established HTTP/3 client connection.
func DialH3Tunnel(ctx context.Context, clientConn *http3.ClientConn, template *uritemplate.Template, p H3DialParams) (*cip.Conn, *http.Response, error) {
	proto := strings.TrimSpace(p.WarpConnectIPProtocol)
	if strings.EqualFold(proto, "cf-connect-ip") && strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1" {
		if st := clientConn.Settings(); st != nil {
			log.Printf("masque connect_ip debug: h3 peer settings extended_connect=%v datagrams=%v tag=%s",
				st.EnableExtendedConnect, st.EnableDatagrams, strings.TrimSpace(p.Tag))
		} else {
			log.Printf("masque connect_ip debug: h3 peer settings=nil tag=%s", strings.TrimSpace(p.Tag))
		}
	}
	var conn *cip.Conn
	var rsp *http.Response
	var err error
	if proto == "" && p.ExtraRequestHeaders == nil {
		conn, rsp, err = cip.Dial(ctx, clientConn, template, strings.TrimSpace(p.BearerToken))
	} else {
		conn, rsp, err = cip.DialWithOptions(ctx, clientConn, template, BuildH3DialOptions(p))
	}
	if err != nil || conn == nil {
		return conn, rsp, err
	}
	LogCfConnectIPHTTPResponse(rsp, proto)
	return conn, rsp, nil
}

// LogCfConnectIPHTTPResponse logs CONNECT response metadata (header names only) for consumer WARP.
func LogCfConnectIPHTTPResponse(rsp *http.Response, proto string) {
	if rsp == nil || !strings.EqualFold(strings.TrimSpace(proto), "cf-connect-ip") {
		return
	}
	names := make([]string, 0, len(rsp.Header))
	for k := range rsp.Header {
		names = append(names, k)
	}
	slices.Sort(names)
	log.Printf("masque connect_ip bootstrap: cf-connect-ip CONNECT status=%d response_header_keys=%v", rsp.StatusCode, names)
}

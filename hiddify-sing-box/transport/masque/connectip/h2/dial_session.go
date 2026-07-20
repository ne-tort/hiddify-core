package h2

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	cip "github.com/quic-go/connect-ip-go"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/yosida95/uritemplate/v3"
)

// SessionDialHost wires production CONNECT-IP HTTP/2 session dial from package masque (phase 19 bridge).
type SessionDialHost interface {
	Tag() string
	WarpConnectIPProtocol() string
	TemplateIP() *uritemplate.Template
	ErrNoTemplateIP() error
	OverlayDialAddr() string
	PrimaryDialHost() string
	WarpAlternateHost(primary string) string
	IsExtendedConnectUnsupported(err error) bool
	EnsureH2Transport(ctx context.Context) (http.RoundTripper, error)
	TCPRoundTripper(defaultTransport http.RoundTripper) http.RoundTripper
	H2DialParams() mcip.H2DialParams
	BootstrapParams() mcip.SessionBootstrapParams
	OnCtxCanceled()
}

// DialSession opens CONNECT-IP over the session HTTP/2 transport pool (Extended CONNECT + bootstrap).
func DialSession(ctx context.Context, host SessionDialHost) (*cip.Conn, error) {
	dialAddr := host.OverlayDialAddr()
	select {
	case <-ctx.Done():
		host.OnCtxCanceled()
		return nil, context.Cause(ctx)
	default:
	}
	if host.TemplateIP() == nil {
		return nil, host.ErrNoTemplateIP()
	}
	log.Printf("masque_http_layer_attempt layer=h2 tag=%s connect_ip=1 dial=%s", strings.TrimSpace(host.Tag()), dialAddr)

	proto := strings.TrimSpace(host.WarpConnectIPProtocol())
	primaryHost := strings.TrimSpace(host.PrimaryDialHost())
	altHost := ""
	if strings.EqualFold(proto, "cf-connect-ip") {
		altHost = host.WarpAlternateHost(primaryHost)
	}

	tr, err := host.EnsureH2Transport(ctx)
	if err != nil {
		return nil, fmt.Errorf("masque connect-ip h2: %w", err)
	}
	rt := host.TCPRoundTripper(tr)

	conn, err := DialH2TunnelWithBootstrap(ctx, rt, host.TemplateIP(), host.H2DialParams(), host.BootstrapParams())
	if err != nil {
		if altHost != "" && host.IsExtendedConnectUnsupported(err) {
			log.Printf("masque h2 cf-connect-ip: tcp dial uses sibling %s of quic dataplane %s; peer omits RFC8441 SETTINGS_ENABLE_CONNECT_PROTOCOL (cannot run cf-connect-ip over H2 on this edge) tag=%s",
				altHost, primaryHost, strings.TrimSpace(host.Tag()))
		}
		return nil, fmt.Errorf("masque connect-ip h2: %w", err)
	}
	return conn, nil
}

// DialH2Session is an alias for DialSession (legacy call sites).
func DialH2Session(ctx context.Context, host SessionDialHost) (*cip.Conn, error) {
	return DialSession(ctx, host)
}

// H2SessionDialHost is a legacy alias for SessionDialHost.
type H2SessionDialHost = SessionDialHost

package masque

import (
	"context"
	"net"
	"net/http"

	connectip "github.com/quic-go/connect-ip-go"
	qmasque "github.com/quic-go/masque-go"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/httpx"
	"github.com/yosida95/uritemplate/v3"
)

// BindHookLayer wires a test-only httpx.HookLayer onto coreSession injection points.
// Phase A0 bridge; production session construction does not call this.
func BindHookLayer(s *coreSession, layer *httpx.HookLayer) {
	if s == nil || layer == nil {
		return
	}
	name := layer.LayerName()
	if name == option.MasqueHTTPLayerH2 || name == option.MasqueHTTPLayerH3 {
		s.UDPHTTPLayer.Store(name)
	}
	hooks := layer.Hooks()
	if hooks.ConnectIP != nil {
		hook := hooks.ConnectIP
		s.dialConnectIPAttemptHook = func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
			return hook(ctx, useHTTP2)
		}
	}
	if hooks.UDPDial != nil {
		hook := hooks.UDPDial
		s.udpDial = func(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
			return hook(ctx, client, template, target)
		}
	}
	if hooks.TCPRoundTrip != nil {
		hook := hooks.TCPRoundTrip
		s.TCPRoundTripper = hookRoundTripper{fn: hook}
	}
}

type hookRoundTripper struct {
	fn func(*http.Request) (*http.Response, error)
}

func (h hookRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return h.fn(req)
}

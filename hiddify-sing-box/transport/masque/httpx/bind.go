package httpx

import (
	"context"
	"net"
	"net/http"

	connectip "github.com/quic-go/connect-ip-go"
	qmasque "github.com/quic-go/masque-go"
	"github.com/sagernet/sing-box/option"
	"github.com/yosida95/uritemplate/v3"
)

// HookSession receives test injection hooks from BindHookLayer.
// Implemented by masque.coreSession; production construction does not call BindHookLayer.
type HookSession interface {
	BindHTTPLayerHooks(layerName string, hooks HookFuncs)
}

// BindHookLayer wires a test-only HookLayer onto session injection points.
func BindHookLayer(session HookSession, layer *HookLayer) {
	if session == nil || layer == nil {
		return
	}
	session.BindHTTPLayerHooks(layer.LayerName(), layer.Hooks())
}

// hookRoundTripper adapts HookFuncs.TCPRoundTrip to http.RoundTripper.
type hookRoundTripper struct {
	fn func(*http.Request) (*http.Response, error)
}

func (h hookRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return h.fn(req)
}

// ApplyHookFuncs maps HookFuncs onto coreSession fields (masque package).
func ApplyHookFuncs(
	setUDPHTTPLayer func(string),
	setDialConnectIPAttemptHook func(func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error)),
	setUDPDial func(func(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error)),
	setTCPRoundTripper func(http.RoundTripper),
	layerName string,
	hooks HookFuncs,
) {
	if layerName == option.MasqueHTTPLayerH2 || layerName == option.MasqueHTTPLayerH3 {
		setUDPHTTPLayer(layerName)
	}
	if hooks.ConnectIP != nil {
		hook := hooks.ConnectIP
		setDialConnectIPAttemptHook(func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
			return hook(ctx, useHTTP2)
		})
	}
	if hooks.UDPDial != nil {
		hook := hooks.UDPDial
		setUDPDial(func(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
			return hook(ctx, client, template, target)
		})
	}
	if hooks.TCPRoundTrip != nil {
		hook := hooks.TCPRoundTrip
		setTCPRoundTripper(hookRoundTripper{fn: hook})
	}
}

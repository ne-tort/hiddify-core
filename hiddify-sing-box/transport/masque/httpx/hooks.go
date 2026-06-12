package httpx

import (
	"context"
	"errors"
	"net"
	"net/http"

	connectip "github.com/quic-go/connect-ip-go"
	qmasque "github.com/quic-go/masque-go"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

// HookFuncs mirrors coreSession test injection points (phase A0).
// Bind to a session via masque.BindHookLayer — production code leaves these nil.
type HookFuncs struct {
	// ConnectIP substitutes dialConnectIPAttemptHook (CONNECT-IP).
	ConnectIP func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error)
	// UDPDial substitutes udpDial (CONNECT-UDP on H3).
	UDPDial func(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error)
	// TCPRoundTrip substitutes tcpRoundTripper (CONNECT-stream H3 round-trip).
	TCPRoundTrip func(req *http.Request) (*http.Response, error)
}

// HookLayer implements HTTPLayer for tests by delegating to HookFuncs once bound on coreSession.
type HookLayer struct {
	name  string
	hooks HookFuncs
}

var _ HTTPLayer = (*HookLayer)(nil)

var errHookLayerUnbound = errors.New("httpx: HookLayer requires masque.BindHookLayer on coreSession")

// NewHookLayer builds a fake overlay for package tests. name must be "h2" or "h3".
func NewHookLayer(name string, hooks HookFuncs) *HookLayer {
	return &HookLayer{name: name, hooks: hooks}
}

func (h *HookLayer) LayerName() string {
	if h == nil {
		return ""
	}
	return h.name
}

// Hooks returns the configured injection funcs (read-only snapshot).
func (h *HookLayer) Hooks() HookFuncs {
	if h == nil {
		return HookFuncs{}
	}
	return h.hooks
}

func (h *HookLayer) DialConnectStream(context.Context, M.Socksaddr) (net.Conn, error) {
	return nil, errHookLayerUnbound
}

func (h *HookLayer) OpenIPSession(context.Context) (IPPacketSession, error) {
	return nil, errHookLayerUnbound
}

func (h *HookLayer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errHookLayerUnbound
}

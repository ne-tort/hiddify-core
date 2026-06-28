package server

import (
	"fmt"
	"net/http"
	"strings"

	connectipgo "github.com/quic-go/connect-ip-go"
	cipserver "github.com/sagernet/sing-box/protocol/masque/server/connectip"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

// ConnectIPHandlerHost carries endpoint state for HandleConnectIPRequest.
type ConnectIPHandlerHost = cipserver.Host

var defaultConnectIPHandler = cipserver.Handler{
	Hooks: cipserver.Hooks{
		RequestErrorHTTPStatus:   ConnectIPRequestErrorHTTPStatus,
		RequestErrorClass:        ConnectIPRequestErrorClass,
		RouteSetupTimeout:        ConnectIPRouteSetupTimeout,
		RouteAdvertiseErrorClass: ConnectIPRouteAdvertiseErrorClass,
		RouteBlocked:             connectIPRouteBlockedHook,
	},
}

// HandleConnectIPRequest serves CONNECT-IP via the thin server shell (see connectip/handler.go).
func HandleConnectIPRequest(host ConnectIPHandlerHost, w http.ResponseWriter, r *http.Request, ipTemplate *uritemplate.Template) {
	defaultConnectIPHandler.HandleConnectIPRequest(host, w, r, ipTemplate)
}

func connectIPRouteBlockedHook(host cipserver.Host, r *http.Request, conn *connectipgo.Conn) {
	packetConn := NewConnectIPNetPacketConn(conn)
	var metadata adapter.InboundContext
	metadata.Inbound = host.Tag
	metadata.InboundType = host.Type
	metadata.Source = M.ParseSocksaddr(r.RemoteAddr)
	metadata.Destination = M.Socksaddr{}
	metadata.User = strings.TrimSpace(r.RemoteAddr)
	if host.Logger != nil {
		host.Logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip route dispatch router_type=%T destination=dynamic", host.Router))
	}
	RouteConnectIPBlocked(host.Router, r.Context(), packetConn, metadata, host.Logger, host.Options, host.Dialer)
}

func connectIPHandlerHost(host MuxHost) ConnectIPHandlerHost {
	return ConnectIPHandlerHost{
		Tag:             host.Tag,
		Type:            host.Type,
		Options:         host.Options,
		Router:          host.Router,
		Logger:          host.Logger,
		Dialer:          host.Dialer,
		Authorize:       host.Authorize,
		RequestForParse: host.RequestForParse,
		RelaxAuthority:  host.RelaxAuthority,
		TemplateField:   TemplateFieldIP,
	}
}

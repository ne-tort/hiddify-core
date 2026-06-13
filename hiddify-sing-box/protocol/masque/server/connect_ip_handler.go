package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

// ConnectIPHandlerHost carries endpoint state for HandleConnectIPRequest.
type ConnectIPHandlerHost struct {
	Tag             string
	Type            string
	Options         option.MasqueEndpointOptions
	Router          adapter.Router
	Logger          log.ContextLogger
	Dialer          net.Dialer
	Authorize       func(*http.Request) bool
	RequestForParse func(*http.Request, *uritemplate.Template, bool) *http.Request
	RelaxAuthority  func(option.MasqueEndpointOptions, string) bool
}

// sharedConnectIPProxy is a process-wide connectip.Proxy singleton. connect-ip-go.Proxy is a
// zero-size stateless type (no per-session fields); session state lives in the returned Conn.
// Safe to share across concurrent CONNECT-IP handlers (see OPTIMIZATION.md / GAPS G34).
var sharedConnectIPProxy = &connectip.Proxy{}

// HandleConnectIPRequest serves CONNECT-IP: parse, proxy bootstrap, address/route setup, then
// blocks until the packet-plane TCP forwarder exits. On HTTP/2 Extended CONNECT there is no
// http3.HTTPStreamer hijack; blocking here prevents net/http from finalizing the response while
// RouteConnectIPBlocked goroutines are still running.
func HandleConnectIPRequest(host ConnectIPHandlerHost, w http.ResponseWriter, r *http.Request, ipTemplate *uritemplate.Template) {
	if host.Logger != nil {
		host.Logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip request method=%s remote=%s uri=%s", r.Method, r.RemoteAddr, r.URL.String()))
	}
	if host.Authorize != nil && !host.Authorize(r) {
		if host.Logger != nil {
			host.Logger.DebugContext(r.Context(), "masque connect-ip auth denied status=401")
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	parseR := host.RequestForParse(r, ipTemplate, host.RelaxAuthority(host.Options, TemplateFieldIP))
	req, err := connectip.ParseRequest(parseR, ipTemplate)
	if err != nil {
		status := ConnectIPRequestErrorHTTPStatus(err)
		if host.Logger != nil {
			host.Logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip parse denied status=%d error_class=%s err=%v", status, ConnectIPRequestErrorClass(status), err))
		}
		w.WriteHeader(status)
		return
	}
	conn, err := sharedConnectIPProxy.Proxy(w, r, req)
	if err != nil {
		if host.Logger != nil {
			host.Logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip proxy failed status=502 err=%v", err))
		}
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	routeCtx, cancelRoute := context.WithTimeout(r.Context(), ConnectIPRouteSetupTimeout())
	assignErr := conn.AssignAddresses(routeCtx, []netip.Prefix{
		netip.MustParsePrefix("198.18.0.1/32"),
		netip.MustParsePrefix("fd00::1/128"),
	})
	if assignErr != nil {
		cancelRoute()
		if host.Logger != nil {
			host.Logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip address assign failed status=502 err=%v", assignErr))
		}
		_ = conn.Close()
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	routeErr := conn.AdvertiseRoute(routeCtx, []connectip.IPRoute{
		{StartIP: netip.IPv4Unspecified(), EndIP: netip.MustParseAddr("255.255.255.255"), IPProtocol: 0},
		{StartIP: netip.IPv6Unspecified(), EndIP: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), IPProtocol: 0},
	})
	cancelRoute()
	if routeErr != nil {
		if host.Logger != nil {
			host.Logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip route advertise failed status=502 error_class=%s err=%v", ConnectIPRouteAdvertiseErrorClass(routeErr), routeErr))
		}
		_ = conn.Close()
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	if host.Logger != nil {
		host.Logger.DebugContext(r.Context(), "masque connect-ip route ready status=200")
	}
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
	}
}

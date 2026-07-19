package connectip

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	connectipgo "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/session"
	"github.com/yosida95/uritemplate/v3"
)

// Hooks wires server-side helpers from protocol/masque/server (connect_ip.go).
type Hooks struct {
	RequestErrorHTTPStatus   func(error) int
	RequestErrorClass        func(int) session.ErrorClass
	RouteSetupTimeout        func() time.Duration
	RouteAdvertiseErrorClass func(error) session.ErrorClass
	RouteBlocked             func(host Host, r *http.Request, conn *connectipgo.Conn)
}

// Host carries endpoint state for HandleConnectIPRequest.
type Host struct {
	Tag             string
	Type            string
	Options         option.MasqueEndpointOptions
	Router          adapter.Router
	Logger          log.ContextLogger
	Dialer          net.Dialer
	Authorize       func(*http.Request) bool
	RequestForParse func(*http.Request, *uritemplate.Template, bool) *http.Request
	RelaxAuthority  func(option.MasqueEndpointOptions, string) bool
	TemplateField   string
}

// Handler serves CONNECT-IP over HTTP/2 (capsules) or HTTP/3 (datagrams).
type Handler struct {
	Hooks Hooks
}

// sharedConnectIPProxy is a process-wide connect-ip-go.Proxy singleton. connect-ip-go.Proxy is a
// zero-size stateless type (no per-session fields); session state lives in the returned Conn.
// Safe to share across concurrent CONNECT-IP handlers (see OPTIMIZATION.md / GAPS G34).
var sharedConnectIPProxy = &connectipgo.Proxy{}

// SharedProxy returns the process-wide connect-ip-go Proxy singleton (tests/ops).
func SharedProxy() *connectipgo.Proxy {
	return sharedConnectIPProxy
}

// HandleConnectIPRequest serves CONNECT-IP: parse, proxy bootstrap, address/route setup, then
// blocks until the packet-plane TCP relay exits. On HTTP/2 Extended CONNECT there is no
// http3.HTTPStreamer hijack; blocking here prevents net/http from finalizing the response while
// RouteConnectIPBlocked goroutines are still running.
func (h Handler) HandleConnectIPRequest(host Host, w http.ResponseWriter, r *http.Request, ipTemplate *uritemplate.Template) {
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
	// RequestForParse / RelaxAuthority are optional (nil on prod MuxHost); match UDP mux nil-safety.
	parseR := r
	if host.RequestForParse != nil {
		relax := false
		if host.RelaxAuthority != nil {
			relax = host.RelaxAuthority(host.Options, host.TemplateField)
		}
		parseR = host.RequestForParse(r, ipTemplate, relax)
	}
	req, err := connectipgo.ParseRequest(parseR, ipTemplate)
	if err != nil {
		status := h.Hooks.RequestErrorHTTPStatus(err)
		if host.Logger != nil {
			host.Logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip parse denied status=%d error_class=%s err=%v", status, h.Hooks.RequestErrorClass(status), err))
		}
		w.WriteHeader(status)
		return
	}
	conn, err := sharedConnectIPProxy.Proxy(w, r, req)
	if err != nil {
		if host.Logger != nil {
			host.Logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip proxy failed err=%v", err))
		}
		return
	}
	routeCtx, cancelRoute := context.WithTimeout(r.Context(), h.Hooks.RouteSetupTimeout())
	assignErr := conn.AssignAddresses(routeCtx, []netip.Prefix{
		netip.MustParsePrefix("198.18.0.1/32"),
		netip.MustParsePrefix("fd00::1/128"),
	})
	if assignErr != nil {
		cancelRoute()
		if host.Logger != nil {
			host.Logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip address assign failed err=%v", assignErr))
		}
		_ = conn.Close()
		return
	}
	routeErr := conn.AdvertiseRoute(routeCtx, []connectipgo.IPRoute{
		{StartIP: netip.IPv4Unspecified(), EndIP: netip.MustParseAddr("255.255.255.255"), IPProtocol: 0},
		{StartIP: netip.IPv6Unspecified(), EndIP: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), IPProtocol: 0},
	})
	cancelRoute()
	if routeErr != nil {
		if host.Logger != nil {
			host.Logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip route advertise failed error_class=%s err=%v", h.Hooks.RouteAdvertiseErrorClass(routeErr), routeErr))
		}
		_ = conn.Close()
		return
	}
	if host.Logger != nil {
		host.Logger.DebugContext(r.Context(), "masque connect-ip route ready status=200")
	}
	if h.Hooks.RouteBlocked != nil {
		h.Hooks.RouteBlocked(host, r, conn)
	}
}

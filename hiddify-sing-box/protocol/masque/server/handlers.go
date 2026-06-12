package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	qmasque "github.com/quic-go/masque-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

const (
	TemplateFieldUDP = "udp"
	TemplateFieldIP  = "ip"
	TemplateFieldTCP = "tcp"
)

// MuxHost carries endpoint state and callbacks for building the MASQUE server HTTP mux.
type MuxHost struct {
	Tag      string
	Type     string
	Options  option.MasqueEndpointOptions
	Router   adapter.Router
	Logger   log.ContextLogger
	Dialer   net.Dialer
	Authorize func(*http.Request) bool

	ResolveTemplates      func(option.MasqueEndpointOptions) (string, string, string)
	RelaxAuthority        func(option.MasqueEndpointOptions, string) bool
	RequestForParse  func(*http.Request, *uritemplate.Template, bool) *http.Request
	AuthorityMatches func(templateHost, requestHost string, relax bool) bool
	OnUDPProxyCreated       func(*qmasque.Proxy)
}

// BuildMuxHandler constructs the MASQUE server ServeMux (UDP/IP/TCP template paths).
func BuildMuxHandler(host MuxHost, tcpRelay string) (http.Handler, error) {
	udpTemplateRaw, ipTemplateRaw, tcpTemplateRaw := host.ResolveTemplates(host.Options)
	udpTemplate, err := uritemplate.New(udpTemplateRaw)
	if err != nil {
		return nil, E.Cause(err, "invalid server UDP template")
	}
	ipTemplate, err := uritemplate.New(ipTemplateRaw)
	if err != nil {
		return nil, E.Cause(err, "invalid server IP template")
	}
	var tcpTemplate *uritemplate.Template
	var tcpPath string
	if tcpRelay == option.MasqueTCPRelayTemplate {
		var err error
		tcpTemplate, err = uritemplate.New(tcpTemplateRaw)
		if err != nil {
			return nil, E.Cause(err, "invalid server TCP template")
		}
		tcpPath = SanitizeTemplatePathForHTTPMux(PathFromTemplate(tcpTemplateRaw))
	}
	udpPath := SanitizeTemplatePathForHTTPMux(PathFromTemplate(udpTemplateRaw))
	ipPath := SanitizeTemplatePathForHTTPMux(PathFromTemplate(ipTemplateRaw))
	mux := http.NewServeMux()
	if ServerThin() {
		if tcpRelay != option.MasqueTCPRelayTemplate || tcpTemplate == nil {
			return nil, E.New("masque server: MASQUE_SERVER_CONNECT_STREAM_ONLY requires tcp_relay template")
		}
		mux.HandleFunc(udpPath, func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
		mux.HandleFunc(ipPath, func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
		tcpRelaxedAuthority := host.RelaxAuthority(host.Options, TemplateFieldTCP)
		mux.HandleFunc(tcpPath, func(w http.ResponseWriter, r *http.Request) {
			HandleTCPConnectRequest(tcpConnectHost(host), w, r, tcpTemplate, tcpRelaxedAuthority)
		})
		return mux, nil
	}
	udpProxy := &qmasque.Proxy{}
	if host.OnUDPProxyCreated != nil {
		host.OnUDPProxyCreated(udpProxy)
	}
	ipProxy := &connectip.Proxy{}
	mux.HandleFunc(udpPath, func(w http.ResponseWriter, r *http.Request) {
		if host.Authorize != nil && !host.Authorize(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		parseR := host.RequestForParse(r, udpTemplate, host.RelaxAuthority(host.Options, TemplateFieldUDP))
		req, err := qmasque.ParseRequest(parseR, udpTemplate)
		if err != nil {
			var perr *qmasque.RequestParseError
			if errors.As(err, &perr) {
				w.WriteHeader(perr.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		HandleConnectUDP(w, r, req, udpProxy)
	})
	mux.HandleFunc(ipPath, func(w http.ResponseWriter, r *http.Request) {
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
		conn, err := ipProxy.Proxy(w, r, req)
		if err != nil {
			if host.Logger != nil {
				host.Logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip proxy failed status=502 err=%v", err))
			}
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		routeCtx, cancelRoute := context.WithTimeout(r.Context(), 2*time.Second)
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
	})
	if tcpRelay != option.MasqueTCPRelayAuthority {
		tcpRelaxedAuthority := host.RelaxAuthority(host.Options, TemplateFieldTCP)
		mux.HandleFunc(tcpPath, func(w http.ResponseWriter, r *http.Request) {
			HandleTCPConnectRequest(tcpConnectHost(host), w, r, tcpTemplate, tcpRelaxedAuthority)
		})
	}
	var httpHandler http.Handler = mux
	if tcpRelay == option.MasqueTCPRelayAuthority {
		// CONNECT by authority may use :path / or *; do not rely on ServeMux "/" alone.
		httpHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if os.Getenv("MASQUE_TRACE_TCP") == "1" {
				fmt.Fprintf(os.Stderr, "masque authority http method=%s url=%s host=%s\n",
					r.Method, r.URL.String(), r.Host)
			}
			if r.Method == http.MethodConnect {
				HandleTCPConnectAuthority(tcpConnectAuthorityHost(host), w, r)
				return
			}
			mux.ServeHTTP(w, r)
		})
	}
	return httpHandler, nil
}

func tcpConnectHost(host MuxHost) TCPConnectHost {
	return TCPConnectHost{
		Options:          host.Options,
		Logger:           host.Logger,
		Dialer:           host.Dialer,
		Authorize:        host.Authorize,
		AuthorityMatches: host.AuthorityMatches,
	}
}

// PathFromTemplate extracts the path segment from a MASQUE URI template URL.
func PathFromTemplate(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "/"
	}
	path := u.Path
	if q := strings.Index(path, "?"); q >= 0 {
		path = path[:q]
	}
	if path == "" {
		return "/"
	}
	return path
}

// SanitizeTemplatePathForHTTPMux maps URI-template path segments to patterns valid for
// net/http.ServeMux (Go 1.22+): wildcard names must be simple identifiers; "{+target_host}"
// from RFC 6570 reserved expansion is not accepted as a mux wildcard name.
func SanitizeTemplatePathForHTTPMux(path string) string {
	path = strings.ReplaceAll(path, "{+target_host*}", "{target_host*}")
	path = strings.ReplaceAll(path, "{+target_host:", "{target_host:")
	path = strings.ReplaceAll(path, "{+target_host}", "{target_host}")
	return path
}

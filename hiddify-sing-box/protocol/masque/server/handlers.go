package server

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	cudpframe "github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
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
	OnUDPProxyCreated       func(*cudprelay.Proxy)
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
	if tcpRelay != option.MasqueTCPRelayTemplate {
		return nil, E.New("masque server: only tcp_relay template is supported")
	}
	tcpTemplate, err := uritemplate.New(tcpTemplateRaw)
	if err != nil {
		return nil, E.Cause(err, "invalid server TCP template")
	}
	tcpPath := SanitizeTemplatePathForHTTPMux(PathFromTemplate(tcpTemplateRaw))
	udpPath := SanitizeTemplatePathForHTTPMux(PathFromTemplate(udpTemplateRaw))
	ipPath := SanitizeTemplatePathForHTTPMux(PathFromTemplate(ipTemplateRaw))
	mux := http.NewServeMux()
	if ConnectStreamOnlyServer() {
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
	udpProxy := &cudprelay.Proxy{}
	if host.OnUDPProxyCreated != nil {
		host.OnUDPProxyCreated(udpProxy)
	}
	mux.HandleFunc(udpPath, func(w http.ResponseWriter, r *http.Request) {
		if host.Authorize != nil && !host.Authorize(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		parseR := host.RequestForParse(r, udpTemplate, host.RelaxAuthority(host.Options, TemplateFieldUDP))
		req, err := cudpframe.ParseRequest(parseR, udpTemplate)
		if err != nil {
			var perr *cudpframe.RequestParseError
			if errors.As(err, &perr) {
				w.WriteHeader(perr.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		HandleConnectUDP(w, r, req, udpProxy, ConnectUDPTargetPolicy{
			AllowPrivateTargets: host.Options.AllowPrivateTargets,
			AllowedTargetPorts:  host.Options.AllowedTargetPorts,
			BlockedTargetPorts:  host.Options.BlockedTargetPorts,
		})
	})
	mux.HandleFunc(ipPath, func(w http.ResponseWriter, r *http.Request) {
		HandleConnectIPRequest(connectIPHandlerHost(host), w, r, ipTemplate)
	})
	tcpRelaxedAuthority := host.RelaxAuthority(host.Options, TemplateFieldTCP)
	mux.HandleFunc(tcpPath, func(w http.ResponseWriter, r *http.Request) {
		HandleTCPConnectRequest(tcpConnectHost(host), w, r, tcpTemplate, tcpRelaxedAuthority)
	})
	return mux, nil
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

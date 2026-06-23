package server

import (
	"net"
	"net/http"

	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/yosida95/uritemplate/v3"
)

// TemplateAuthorityHooks wires masque-root template parse and :authority relax callbacks.
type TemplateAuthorityHooks struct {
	ResolveTemplates func(option.MasqueEndpointOptions) (udp, ip, tcp string)
	RelaxAuthority   func(option.MasqueEndpointOptions, string) bool
	RequestForParse  func(*http.Request, *uritemplate.Template, bool) *http.Request
	AuthorityMatches func(templateHost, requestHost string, relax bool) bool
}

// EndpointMuxFields carries ServerEndpoint state for mux and CONNECT-stream handlers.
type EndpointMuxFields struct {
	Tag      string
	Type     string
	Options  option.MasqueEndpointOptions
	Router   adapter.Router
	Logger   log.ContextLogger
	Dialer   net.Dialer
	Authorize func(*http.Request) bool
	Hooks    TemplateAuthorityHooks
	OnUDPProxyCreated func(*cudprelay.Proxy)
}

// BuildEndpointMuxHost constructs MuxHost from endpoint adapter fields.
func BuildEndpointMuxHost(f EndpointMuxFields) MuxHost {
	return MuxHost{
		Tag:                    f.Tag,
		Type:                   f.Type,
		Options:                f.Options,
		Router:                 f.Router,
		Logger:                 f.Logger,
		Dialer:                 f.Dialer,
		Authorize:              f.Authorize,
		ResolveTemplates:       f.Hooks.ResolveTemplates,
		RelaxAuthority:         f.Hooks.RelaxAuthority,
		RequestForParse:        f.Hooks.RequestForParse,
		AuthorityMatches:       f.Hooks.AuthorityMatches,
		OnUDPProxyCreated:      f.OnUDPProxyCreated,
	}
}

// BuildTCPConnectHost constructs CONNECT-stream handler dependencies from endpoint fields.
func BuildTCPConnectHost(f EndpointMuxFields) TCPConnectHost {
	return TCPConnectHost{
		Options:          f.Options,
		Logger:           f.Logger,
		Dialer:           f.Dialer,
		Authorize:        f.Authorize,
		AuthorityMatches: f.Hooks.AuthorityMatches,
	}
}

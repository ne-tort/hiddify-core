package config

import (
	"net"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

const (
	masqueDefaultTemplateUDP = "/masque/udp/{target_host}/{target_port}"
	masqueDefaultTemplateTCP = "/masque/tcp/{target_host}/{target_port}"
)

// patchMasqueClientEndpoints fills minimal MASQUE client endpoints from s-ui subscriptions
// (outbound_tls, path templates, stable http_layer) before validate/start.
func patchMasqueClientEndpoints(options *option.Options) {
	if options == nil {
		return
	}
	for i := range options.Endpoints {
		patchMasqueClientEndpoint(&options.Endpoints[i])
	}
}

func patchMasqueClientEndpoint(ep *option.Endpoint) {
	if ep == nil {
		return
	}
	switch ep.Type {
	case C.TypeMasque:
		opts := masqueEndpointOptions(ep)
		if opts == nil {
			return
		}
		applyMasqueClientDefaults(opts)
		ep.Options = opts
	case C.TypeWarpMasque:
		opts := warpMasqueEndpointOptions(ep)
		if opts == nil {
			return
		}
		applyMasqueClientDefaults(&opts.MasqueEndpointOptions)
		ep.Options = opts
	}
}

func masqueEndpointOptions(ep *option.Endpoint) *option.MasqueEndpointOptions {
	if opts, ok := ep.Options.(*option.MasqueEndpointOptions); ok {
		return opts
	}
	if opts, ok := ep.Options.(option.MasqueEndpointOptions); ok {
		return &opts
	}
	return nil
}

func warpMasqueEndpointOptions(ep *option.Endpoint) *option.WarpMasqueEndpointOptions {
	if opts, ok := ep.Options.(*option.WarpMasqueEndpointOptions); ok {
		return opts
	}
	if opts, ok := ep.Options.(option.WarpMasqueEndpointOptions); ok {
		return &opts
	}
	return nil
}

func applyMasqueClientDefaults(opts *option.MasqueEndpointOptions) {
	if opts == nil || isMasqueServerEndpoint(opts) {
		return
	}

	hadOutboundTLS := opts.OutboundTLS != nil
	if opts.OutboundTLS == nil {
		tls := &option.OutboundTLSOptions{
			Enabled: true,
		}
		if host := strings.TrimSpace(opts.Server); host != "" && masqueLooksLikeHostname(host) {
			tls.ServerName = host
		}
		opts.OutboundTLS = tls
	}

	if strings.TrimSpace(opts.TemplateUDP) == "" {
		opts.TemplateUDP = masqueDefaultTemplateUDP
	}
	if strings.TrimSpace(opts.TemplateTCP) == "" {
		opts.TemplateTCP = masqueDefaultTemplateTCP
	}

	layer := strings.TrimSpace(opts.HTTPLayer)
	if !hadOutboundTLS &&
		strings.TrimSpace(opts.Server) != "" &&
		(layer == "" || strings.EqualFold(layer, option.MasqueHTTPLayerAuto)) {
		opts.HTTPLayer = option.MasqueHTTPLayerH3
	}
}

func isMasqueServerEndpoint(opts *option.MasqueEndpointOptions) bool {
	if opts == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(opts.Role), option.MasqueRoleServer) {
		return true
	}
	if strings.TrimSpace(opts.Listen) != "" || opts.ListenPort > 0 {
		return true
	}
	return false
}

func masqueLooksLikeHostname(server string) bool {
	host := strings.TrimSpace(server)
	if host == "" {
		return false
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return false
	}
	return net.ParseIP(host) == nil
}

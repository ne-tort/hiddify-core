package config

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// patchMasqueClientEndpoints previously filled subscription gaps (outbound_tls / templates / http_layer).
// That mutation broke Reality/H2 transparency; MASQUE endpoints now pass through to sing-box unchanged.
// Kept as a no-op hook so call sites in parser/builder stay stable.
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
	case C.TypeMasque, C.TypeWarpMasque:
		// Passthrough: do not invent TLS, http_layer, or templates.
		return
	}
}

// applyMasqueClientDefaults is retained for tests that assert the no-op policy.
func applyMasqueClientDefaults(opts *option.MasqueEndpointOptions) {
	_ = opts
}

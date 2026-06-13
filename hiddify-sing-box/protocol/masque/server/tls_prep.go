package server

import (
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// PrepareInboundTLS returns a copy of inbound TLS with Enabled set and ALPN defaults for QUIC and TCP listeners.
func PrepareInboundTLS(in *option.InboundTLSOptions, httpLayerHint string, _ bool) (*option.InboundTLSOptions, error) {
	if in == nil {
		return nil, E.New("masque server: tls is required")
	}
	out := *in
	out.Enabled = true
	layer := strings.ToLower(strings.TrimSpace(httpLayerHint))
	if layer == "" {
		layer = option.MasqueHTTPLayerH3
	}
	if len(out.ALPN) == 0 {
		switch layer {
		case option.MasqueHTTPLayerH2:
			out.ALPN = []string{"h2", "http/1.1"}
		case option.MasqueHTTPLayerH3, option.MasqueHTTPLayerAuto:
			fallthrough
		default:
			// MASQUE server listens QUIC/H3 and TCP/H2 on the same port; defaults must advertise
			// both so the TCP listener can negotiate h2 after TLS clone.
			out.ALPN = []string{"h3", "h2", "http/1.1"}
		}
	}
	return &out, nil
}

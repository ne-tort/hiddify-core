package server

import (
	"strings"

	"github.com/sagernet/sing-box/option"
	masquetls "github.com/sagernet/sing-box/protocol/masque/tls"
	E "github.com/sagernet/sing/common/exceptions"
)

// PrepareInboundTLS returns a copy of inbound TLS with Enabled set and ALPN defaults for QUIC and TCP listeners.
// Reality is allowed only with explicit http_layer=h2 (H2-only TCP path; dual/H3 reject).
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
	if err := masquetls.ValidateInboundTLSRealityPriority(&out, layer); err != nil {
		return nil, err
	}
	if len(out.ALPN) == 0 {
		if out.Reality != nil && out.Reality.Enabled {
			// Reality is TCP/H2-only — never advertise h3.
			out.ALPN = masquetls.DefaultH2ServerTCPALPN()
		} else {
			out.ALPN = masquetls.DefaultInboundALPN(layer)
		}
	} else if err := masquetls.ValidateInboundALPN(out.ALPN, layer); err != nil {
		return nil, err
	}
	return &out, nil
}

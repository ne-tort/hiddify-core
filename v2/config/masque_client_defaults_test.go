package config

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestApplyMasqueClientDefaults_isNoOp(t *testing.T) {
	opts := &option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{
			Server:     "wiki.example.com",
			ServerPort: 44433,
		},
		ServerToken: "token",
		HTTPLayer:   option.MasqueHTTPLayerAuto,
	}

	applyMasqueClientDefaults(opts)

	if opts.OutboundTLS != nil {
		t.Fatalf("must not invent outbound_tls: %#v", opts.OutboundTLS)
	}
	if opts.TemplateUDP != "" || opts.TemplateTCP != "" {
		t.Fatalf("must not invent templates: udp=%q tcp=%q", opts.TemplateUDP, opts.TemplateTCP)
	}
	if opts.HTTPLayer != option.MasqueHTTPLayerAuto {
		t.Fatalf("http_layer mutated: %q", opts.HTTPLayer)
	}
}

func TestApplyMasqueClientDefaults_keepsExplicitOutboundTLSUntouched(t *testing.T) {
	opts := &option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "wiki.example.com"},
		OutboundTLS: &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "www.allizom.org",
			UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
			Reality: &option.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: "JwHKF9DzSvmSxmIk_6QuiYJh3h3Xx_vfk00hvgwdvmg",
				ShortID:   "e7f0a91b",
			},
		},
		HTTPLayer: option.MasqueHTTPLayerH2,
	}

	applyMasqueClientDefaults(opts)

	if opts.OutboundTLS.ServerName != "www.allizom.org" {
		t.Fatalf("server_name: %q", opts.OutboundTLS.ServerName)
	}
	if opts.OutboundTLS.Reality == nil || !opts.OutboundTLS.Reality.Enabled {
		t.Fatalf("reality stripped: %#v", opts.OutboundTLS.Reality)
	}
	if opts.OutboundTLS.UTLS == nil || !opts.OutboundTLS.UTLS.Enabled {
		t.Fatalf("utls stripped: %#v", opts.OutboundTLS.UTLS)
	}
	if opts.HTTPLayer != option.MasqueHTTPLayerH2 {
		t.Fatalf("http_layer: %q", opts.HTTPLayer)
	}
}

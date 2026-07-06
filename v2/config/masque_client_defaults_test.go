package config

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestApplyMasqueClientDefaults_minimalSubscription(t *testing.T) {
	opts := &option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{
			Server:     "wiki.example.com",
			ServerPort: 44433,
		},
		ServerToken: "token",
		HTTPLayer:   option.MasqueHTTPLayerAuto,
	}

	applyMasqueClientDefaults(opts)

	if opts.OutboundTLS == nil || !opts.OutboundTLS.Enabled {
		t.Fatalf("expected outbound_tls.enabled, got %#v", opts.OutboundTLS)
	}
	if opts.OutboundTLS.ServerName != "wiki.example.com" {
		t.Fatalf("server_name: %q", opts.OutboundTLS.ServerName)
	}
	if opts.TemplateUDP != masqueDefaultTemplateUDP {
		t.Fatalf("template_udp: %q", opts.TemplateUDP)
	}
	if opts.TemplateTCP != masqueDefaultTemplateTCP {
		t.Fatalf("template_tcp: %q", opts.TemplateTCP)
	}
	if opts.HTTPLayer != option.MasqueHTTPLayerH3 {
		t.Fatalf("http_layer: %q", opts.HTTPLayer)
	}
}

func TestApplyMasqueClientDefaults_keepsExplicitOutboundTLS(t *testing.T) {
	opts := &option.MasqueEndpointOptions{
		ServerOptions: option.ServerOptions{Server: "wiki.example.com"},
		OutboundTLS: &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "custom.example.com",
		},
		HTTPLayer: option.MasqueHTTPLayerAuto,
	}

	applyMasqueClientDefaults(opts)

	if opts.OutboundTLS.ServerName != "custom.example.com" {
		t.Fatalf("server_name overwritten: %q", opts.OutboundTLS.ServerName)
	}
	if opts.HTTPLayer != option.MasqueHTTPLayerAuto {
		t.Fatalf("http_layer should stay auto when outbound_tls was explicit: %q", opts.HTTPLayer)
	}
}

func TestApplyMasqueClientDefaults_skipsServerRole(t *testing.T) {
	opts := &option.MasqueEndpointOptions{
		Role:       option.MasqueRoleServer,
		Listen:     "0.0.0.0",
		ListenPort: 443,
	}

	applyMasqueClientDefaults(opts)

	if opts.OutboundTLS != nil {
		t.Fatalf("server endpoint must not get outbound_tls: %#v", opts.OutboundTLS)
	}
}

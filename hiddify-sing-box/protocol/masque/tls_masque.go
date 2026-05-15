package masque

import (
	"context"
	"crypto/tls"
	"net"
	"strings"

	btls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// prepareMasqueServerInboundTLS returns a copy of inbound TLS with Enabled set and ALPN defaults for QUIC vs TCP listeners.
func prepareMasqueServerInboundTLS(in *option.InboundTLSOptions, httpLayerHint string) (*option.InboundTLSOptions, error) {
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
			// both so the TCP listener (see endpoint_server.go) can negotiate h2 after TLS clone.
			out.ALPN = []string{"h3", "h2", "http/1.1"}
		}
	}
	return &out, nil
}

// validateMasqueOutboundTLSWithHTTPLayer rejects incompatible combinations (e.g. uTLS cannot drive QUIC crypto/tls.Config).
func validateMasqueOutboundTLSWithHTTPLayer(out *option.OutboundTLSOptions, httpLayer string) error {
	if out == nil {
		return E.New("masque: outbound_tls is required for client mode")
	}
	if !out.Enabled {
		return E.New("masque: outbound_tls.enabled must be true")
	}
	if out.UTLS != nil && out.UTLS.Enabled {
		hl := strings.ToLower(strings.TrimSpace(httpLayer))
		if hl == "" {
			hl = option.MasqueHTTPLayerH3
		}
		switch hl {
		case option.MasqueHTTPLayerH3:
			return E.New("masque: outbound_tls.utls is incompatible with http_layer h3 (QUIC uses crypto/tls without uTLS fingerprinting)")
		case option.MasqueHTTPLayerAuto:
			return E.New("masque: outbound_tls.utls is incompatible with http_layer auto (QUIC path may be chosen)")
		case option.MasqueHTTPLayerH2:
			// TCP TLS: uTLS supported via sing-box client handshake.
		default:
			return E.New("masque: invalid http_layer for utls check: ", httpLayer)
		}
	}
	return nil
}

// stripOutboundTLSForQUIC returns a copy suitable for crypto/tls used by quic-go (no uTLS / Reality).
func stripOutboundTLSForQUIC(o option.OutboundTLSOptions) option.OutboundTLSOptions {
	o.UTLS = nil
	o.Reality = nil
	return o
}

// buildMasqueQUICStdTLSConfig builds *tls.Config for QUIC/HTTP3 from sing-box outbound TLS (stdlib only).
func buildMasqueQUICStdTLSConfig(ctx context.Context, logger log.ContextLogger, serverAddr string, out *option.OutboundTLSOptions) (*tls.Config, error) {
	if out == nil {
		return nil, E.New("masque: nil outbound_tls")
	}
	quicOpt := stripOutboundTLSForQUIC(*out)
	quicOpt.Enabled = true
	cfg, err := btls.NewSTDClient(ctx, logger, serverAddr, quicOpt)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, E.New("masque: empty TLS client config")
	}
	std, err := cfg.STDConfig()
	if err != nil {
		return nil, err
	}
	if std == nil {
		return nil, E.New("masque: TLS STDConfig is nil")
	}
	return std, nil
}

// buildMasqueTCPDialTLS returns a dial wrapper for HTTP/2 overlay: uses sing-box TLS client (std or uTLS).
func buildMasqueTCPDialTLS(ctx context.Context, logger log.ContextLogger, serverAddr string, out *option.OutboundTLSOptions) (func(context.Context, net.Conn, []string, string) (net.Conn, error), error) {
	if out == nil {
		return nil, E.New("masque: nil outbound_tls")
	}
	full := *out
	full.Enabled = true
	tlsClient, err := btls.NewClientWithOptions(btls.ClientOptions{
		Context:       ctx,
		Logger:        logger,
		ServerAddress: serverAddr,
		Options:       full,
	})
	if err != nil {
		return nil, err
	}
	if tlsClient == nil {
		return nil, E.New("masque: tcp tls client is nil")
	}
	return func(ctx context.Context, raw net.Conn, nextProtos []string, _ string) (net.Conn, error) {
		tlsClient.SetNextProtos(nextProtos)
		return btls.ClientHandshake(ctx, raw, tlsClient)
	}, nil
}

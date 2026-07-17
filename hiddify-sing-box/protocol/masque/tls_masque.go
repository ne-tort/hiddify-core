package masque

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	masquetls "github.com/sagernet/sing-box/protocol/masque/tls"
)

// validateMasqueOutboundTLSWithHTTPLayer rejects incompatible combinations (e.g. uTLS cannot drive QUIC crypto/tls.Config).
func validateMasqueOutboundTLSWithHTTPLayer(out *option.OutboundTLSOptions, httpLayer string) error {
	return masquetls.ValidateOutboundTLSWithHTTPLayer(out, httpLayer)
}

// stripOutboundTLSForQUIC returns a copy suitable for crypto/tls used by quic-go (no uTLS / Reality).
func stripOutboundTLSForQUIC(o option.OutboundTLSOptions) option.OutboundTLSOptions {
	return masquetls.StripOutboundTLSForQUIC(o)
}

// buildMasqueQUICStdTLSConfig builds *tls.Config for QUIC/HTTP3 from sing-box outbound TLS (stdlib only).
func buildMasqueQUICStdTLSConfig(ctx context.Context, logger log.ContextLogger, serverAddr string, out *option.OutboundTLSOptions, httpLayer string) (*tls.Config, error) {
	return masquetls.BuildQUICStdTLSConfig(ctx, logger, serverAddr, out, httpLayer)
}

// buildMasqueTCPDialTLS returns a dial wrapper for HTTP/2 overlay: uses sing-box TLS client (std or uTLS).
func buildMasqueTCPDialTLS(ctx context.Context, logger log.ContextLogger, serverAddr string, out *option.OutboundTLSOptions, httpLayer string) (func(context.Context, net.Conn, []string, string) (net.Conn, error), error) {
	return masquetls.BuildTCPDialTLS(ctx, logger, serverAddr, out, httpLayer)
}

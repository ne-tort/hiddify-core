package masquetls

import (
	"context"
	"crypto/tls"
	"net"

	btls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// BuildQUICStdTLSConfig builds *tls.Config for QUIC/HTTP3 from sing-box outbound TLS (stdlib only).
// Shared stack with H2: same OutboundTLSOptions after PrepareOutboundTLSForLayer; QUIС-incompatible
// knobs stripped via StripOutboundTLSForQUIC (see ignore.go). tls_tricks are not applied on QUIС.
func BuildQUICStdTLSConfig(ctx context.Context, logger log.ContextLogger, serverAddr string, out *option.OutboundTLSOptions, httpLayer string) (*tls.Config, error) {
	if out == nil {
		return nil, E.New("masque: nil outbound_tls")
	}
	prepared := PrepareOutboundTLSForLayer(*out, httpLayer)
	quicOpt := StripOutboundTLSForQUIC(prepared)
	// QUIС handshake must advertise h3; never drop user tokens (e.g. auto ["h3","h2",…]).
	quicOpt.ALPN = EnsureH3InALPN(quicOpt.ALPN)
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

// BuildTCPDialTLS returns a dial wrapper for HTTP/2 overlay (STD or uTLS via NewClientWithOptions).
// Applies tls_tricks (mixedcase_sni) before handshake; uTLS stays enabled for TCP when set.
//
// Reality ALPN policy (VLESS parity, MASQUE-only — does not patch common/tls):
//   - empty user alpn → preserve fingerprint ALPN (no EnsureH2 / no SetNextProtos wipe);
//     Chrome parrot already advertises h2 for CONNECT-stream.
//   - explicit user alpn → FilterTCPALPN + EnsureH2, then SetNextProtos (like VLESS+HTTP).
func BuildTCPDialTLS(ctx context.Context, logger log.ContextLogger, serverAddr string, out *option.OutboundTLSOptions, httpLayer string) (func(context.Context, net.Conn, []string, string) (net.Conn, error), error) {
	if out == nil {
		return nil, E.New("masque: nil outbound_tls")
	}
	preserveFPALPN := PreserveUTLSFingerprintALPN(out)
	full := PrepareOutboundTLSForLayer(*out, httpLayer)
	if !preserveFPALPN {
		full.ALPN = EnsureH2InALPN(full.ALPN)
	}
	var err error
	full, err = ApplyOutboundTLSTricks(full, serverAddr)
	if err != nil {
		return nil, err
	}
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
	utlsEnabled := full.UTLS != nil && full.UTLS.Enabled
	if err := ensureUTLSClientWhenRequested(tlsClient, utlsEnabled); err != nil {
		return nil, err
	}
	return func(ctx context.Context, raw net.Conn, nextProtos []string, _ string) (net.Conn, error) {
		if preserveFPALPN {
			// Ignore transport ClientTLSConfig NextProtos (often ["h2"]): any non-empty
			// SetNextProtos makes Reality overwrite parrot ALPN and drop Chrome GREASE.
			tlsClient.SetNextProtos(nil)
			return btls.ClientHandshake(ctx, raw, tlsClient)
		}
		protos := nextProtos
		if len(protos) == 0 {
			protos = full.ALPN
		}
		tlsClient.SetNextProtos(ApplyH2ClientNextProtos(protos))
		return btls.ClientHandshake(ctx, raw, tlsClient)
	}, nil
}

func ensureUTLSClientWhenRequested(tlsClient btls.Config, utlsEnabled bool) error {
	if !utlsEnabled {
		return nil
	}
	if _, err := tlsClient.STDConfig(); err == nil {
		return E.New("masque: outbound_tls.utls.enabled but TLS client is stdlib (expected uTLS)")
	}
	return nil
}

// UsesUTLSClient reports whether NewClientWithOptions selected a non-STD (uTLS/Reality) client.
func UsesUTLSClient(tlsClient btls.Config) bool {
	if tlsClient == nil {
		return false
	}
	_, err := tlsClient.STDConfig()
	return err != nil
}

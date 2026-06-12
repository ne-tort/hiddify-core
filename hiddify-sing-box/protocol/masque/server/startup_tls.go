package server

import (
	"context"
	"crypto/tls"

	"github.com/quic-go/quic-go/http3"
	btls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// StartupTLSOutcome holds TLS configs prepared during ServerEndpoint.Start.
type StartupTLSOutcome struct {
	HTTP3TLS      *tls.Config
	CollateralTLS *tls.Config
	SingServerTLS btls.ServerConfig
	UseStdTLS     bool
}

// StartupTLSConfig inputs for inbound TLS before dual-bind listen.
type StartupTLSConfig struct {
	Ctx              context.Context
	InboundTLS       *option.InboundTLSOptions
	HTTPLayer        string
	AuthorityH3Only  bool
	AuthorityMinimal bool
	Logger           log.ContextLogger
}

// PrepareMasqueStartupTLS builds HTTP/3 and collateral TLS for full or authority-minimal startup.
func PrepareMasqueStartupTLS(cfg StartupTLSConfig) (*StartupTLSOutcome, error) {
	useStdTLS := cfg.AuthorityMinimal && AuthorityUseStdTLS()
	if useStdTLS {
		stdTLS, tlsErr := LoadAuthorityStdTLS(cfg.InboundTLS)
		if tlsErr != nil {
			return nil, tlsErr
		}
		if cfg.Logger != nil {
			cfg.Logger.Info("masque authority server: std tls (thin parity), minimal=", cfg.AuthorityMinimal)
		}
		return &StartupTLSOutcome{
			HTTP3TLS:  http3.ConfigureTLSConfig(stdTLS),
			UseStdTLS: true,
		}, nil
	}

	inTLS, err := PrepareInboundTLS(cfg.InboundTLS, cfg.HTTPLayer, cfg.AuthorityH3Only)
	if err != nil {
		return nil, err
	}
	srvCfg, err := btls.NewServerWithOptions(btls.ServerOptions{
		Context: cfg.Ctx,
		Logger:  cfg.Logger,
		Options: *inTLS,
	})
	if err != nil {
		return nil, E.Cause(err, "masque server tls")
	}
	if srvCfg == nil {
		return nil, E.New("masque server: tls config is nil")
	}
	if err := srvCfg.Start(); err != nil {
		return nil, E.Cause(err, "masque server tls start")
	}
	baseTLS, err := srvCfg.STDConfig()
	if err != nil {
		_ = srvCfg.Close()
		return nil, E.Cause(err, "masque server tls std config")
	}
	if baseTLS == nil {
		_ = srvCfg.Close()
		return nil, E.New("masque server: tls std config is nil")
	}
	return &StartupTLSOutcome{
		HTTP3TLS:      http3.ConfigureTLSConfig(baseTLS),
		CollateralTLS: baseTLS,
		SingServerTLS: srvCfg,
	}, nil
}

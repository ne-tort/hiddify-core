package server

import (
	"context"
	"net"

	btls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque/auth"
	TM "github.com/sagernet/sing-box/transport/masque"
)

// EndpointLifecycleHooks wires ServerEndpoint atomic state for background serve goroutines.
type EndpointLifecycleHooks struct {
	IsClosing               func() bool
	OnReadyFalse            func()
	OnServeError            func(error)
	OnAuthorityThinServeEnd func()
}

// MasqueEndpointStartResult holds resources produced by a successful RunMasqueEndpointStart.
type MasqueEndpointStartResult struct {
	CompiledAuth    *auth.Compiled
	SingServerTLS   btls.ServerConfig
	AuthorityThin   *TM.AuthorityHTTPServer
	Stack           *MasqueStack
	AuthorityH3Only bool
}

// MasqueEndpointStartConfig drives compile → TLS → handler → listen for ServerEndpoint.Start.
type MasqueEndpointStartConfig struct {
	Ctx       context.Context
	Options   option.MasqueEndpointOptions
	TCPRelay  string
	HTTPLayer string
	MuxHost   MuxHost
	Logger    log.ContextLogger
	Lifecycle EndpointLifecycleHooks
}

// RunMasqueEndpointStart performs the listen/Serve setup shared by ServerEndpoint.Start.
func RunMasqueEndpointStart(cfg MasqueEndpointStartConfig) (MasqueEndpointStartResult, error) {
	var out MasqueEndpointStartResult
	tcpRelay := cfg.TCPRelay
	authorityH3Only, authorityMinimal := AuthorityStartupFlags(tcpRelay, cfg.Options)
	out.AuthorityH3Only = authorityH3Only

	compiled, compileErr := auth.Compile(cfg.Options)
	if compileErr != nil {
		return out, compileErr
	}
	out.CompiledAuth = compiled

	tlsOutcome, tlsErr := PrepareMasqueStartupTLS(StartupTLSConfig{
		Ctx:              cfg.Ctx,
		InboundTLS:       cfg.Options.InboundTLS,
		HTTPLayer:        cfg.HTTPLayer,
		AuthorityH3Only:  authorityH3Only,
		AuthorityMinimal: authorityMinimal,
		Logger:           cfg.Logger,
	})
	if tlsErr != nil {
		return out, tlsErr
	}
	out.SingServerTLS = tlsOutcome.SingServerTLS

	httpHandler, buildErr := BuildStartupHandler(cfg.MuxHost, tcpRelay, cfg.Options)
	if buildErr != nil {
		return out, buildErr
	}

	addr := MasqueListenAddr(cfg.Options.Listen, cfg.Options.ListenPort)
	listenHost, _, _ := net.SplitHostPort(addr)
	if authorityMinimal && tlsOutcome.UseStdTLS {
		thin, thinErr := LaunchAuthorityThinHTTPServer(httpHandler, addr, tlsOutcome.HTTP3TLS, AuthorityThinListenHooks{
			IsClosing: cfg.Lifecycle.IsClosing,
			OnServeError: func(serveErr error) {
				if cfg.Lifecycle.OnServeError != nil {
					cfg.Lifecycle.OnServeError(serveErr)
				}
			},
			OnServeEnd: cfg.Lifecycle.OnAuthorityThinServeEnd,
		})
		if thinErr != nil {
			return out, thinErr
		}
		out.AuthorityThin = thin
		out.Stack = &MasqueStack{
			H3Server:   thin.Server,
			PacketConn: thin.PacketConn,
		}
		return out, nil
	}

	quicCfg := TM.MasqueHTTPServerQUICConfig()
	if authorityH3Only {
		quicCfg = TM.MasqueAuthorityHTTPServerQUICConfig()
	}
	serveHooks := MasqueServeHooks{
		IsClosing:    cfg.Lifecycle.IsClosing,
		OnReadyFalse: cfg.Lifecycle.OnReadyFalse,
		OnServeError: cfg.Lifecycle.OnServeError,
	}
	stack, stackErr := LaunchMasqueStack(LaunchMasqueStackConfig{
		Handler:           httpHandler,
		ListenHost:        listenHost,
		ListenPort:        cfg.Options.ListenPort,
		AuthorityH3Only:   authorityH3Only,
		HTTP3TLS:          tlsOutcome.HTTP3TLS,
		CollateralTLS:     tlsOutcome.CollateralTLS,
		H3QUICConfig:      quicCfg,
		EnableH3Datagrams: !authorityH3Only,
		ValidateUDP: func(pc net.PacketConn) error {
			return TM.ValidateQUICTransportPacketConn(pc, "server_http3_listen")
		},
		Hooks: serveHooks,
	})
	if stackErr != nil {
		return out, stackErr
	}
	out.Stack = stack
	return out, nil
}

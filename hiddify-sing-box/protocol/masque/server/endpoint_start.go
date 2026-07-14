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
	IsClosing    func() bool
	OnReadyFalse func()
	OnServeError func(error)
}

// MasqueEndpointStartResult holds resources produced by a successful RunMasqueEndpointStart.
type MasqueEndpointStartResult struct {
	CompiledAuth  *auth.Compiled
	SingServerTLS btls.ServerConfig
	Stack         *MasqueStack
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

	compiled, compileErr := auth.Compile(cfg.Options)
	if compileErr != nil {
		return out, compileErr
	}
	out.CompiledAuth = compiled

	tlsOutcome, tlsErr := PrepareMasqueStartupTLS(StartupTLSConfig{
		Ctx:        cfg.Ctx,
		InboundTLS: cfg.Options.InboundTLS,
		HTTPLayer:  cfg.HTTPLayer,
		Logger:     cfg.Logger,
	})
	if tlsErr != nil {
		return out, tlsErr
	}
	out.SingServerTLS = tlsOutcome.SingServerTLS

	httpHandler, buildErr := BuildStartupHandler(cfg.MuxHost, tcpRelay, cfg.Options)
	if buildErr != nil {
		return out, buildErr
	}

	listenHost, _, _ := net.SplitHostPort(MasqueListenAddr(cfg.Options.Listen, cfg.Options.ListenPort))
	serveHooks := MasqueServeHooks{
		IsClosing:    cfg.Lifecycle.IsClosing,
		OnReadyFalse: cfg.Lifecycle.OnReadyFalse,
		OnServeError: cfg.Lifecycle.OnServeError,
	}
	stack, stackErr := LaunchMasqueStack(LaunchMasqueStackConfig{
		Handler:           httpHandler,
		ListenHost:        listenHost,
		ListenPort:        cfg.Options.ListenPort,
		HTTP3TLS:          tlsOutcome.HTTP3TLS,
		CollateralTLS:     tlsOutcome.CollateralTLS,
		H3QUICConfig:      TM.MasqueHTTPServerQUICConfig(cfg.Options.CongestionControl),
		EnableH3Datagrams: true,
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

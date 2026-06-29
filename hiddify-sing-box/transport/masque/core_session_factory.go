package masque

import (
	"context"
	"errors"
	"strings"

	"github.com/sagernet/sing-box/transport/masque/session"
)

// CoreClientFactory is the production MASQUE client session factory (explicit ctor; no init-time globals).
type CoreClientFactory struct{}

func (CoreClientFactory) NewSession(ctx context.Context, options ClientOptions) (ClientSession, error) {
	if err := rejectConnectIPHybridTransport(options.TransportMode, options.TCPTransport); err != nil {
		return nil, err
	}
	return buildCoreSession(ctx, options)
}

// DirectClientFactory is the plain direct-TCP backend (CONNECT-stream / CONNECT-UDP without MASQUE overlay).
type DirectClientFactory struct{}

func (DirectClientFactory) NewSession(ctx context.Context, options ClientOptions) (ClientSession, error) {
	return session.NewDirectSession(ctx, options)
}

func rejectConnectIPHybridTransport(transportMode, tcpTransport string) error {
	tm := strings.ToLower(strings.TrimSpace(transportMode))
	tt := strings.ToLower(strings.TrimSpace(tcpTransport))
	if tm == "connect_ip" && tt == "connect_stream" {
		return errors.New("masque: transport_mode connect_ip with tcp_transport connect_stream is not supported")
	}
	return nil
}

func buildCoreSession(ctx context.Context, options ClientOptions) (ClientSession, error) {
	templateUDP, templateIP, templateTCP, err := session.BuildTemplates(options, masqueTemplateHooks())
	if err != nil {
		err = joinTemplateCapability(err)
	}
	if err != nil {
		return nil, err
	}
	cs, udpLayer := session.BootstrapCoreSession(options, templateUDP, templateIP, templateTCP)
	core := &coreSession{CoreSession: cs}
	core.UDPHTTPLayer.Store(udpLayer)
	return core, nil
}

package masque

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"

	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	btls "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque/auth"
	"github.com/sagernet/sing-box/protocol/masque/server"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/yosida95/uritemplate/v3"
)

// ConnectIPServerParseDropTotal exposes the parse-drop counter for tests/ops.
func ConnectIPServerParseDropTotal() uint64 {
	return server.ConnectIPServerParseDropTotal()
}

// ServerEndpoint is the MASQUE server (CONNECT-UDP / CONNECT-IP / CONNECT-stream over HTTP/3 + HTTP/2).
type ServerEndpoint struct {
	endpoint.Adapter
	options      option.MasqueEndpointOptions
	compiledAuth *auth.Compiled
	router       adapter.Router
	logger       log.ContextLogger
	server       *http3.Server
	packetConn   net.PacketConn
	// tcpTLSListener is the TLS listener (HTTP/2 ALPN) dual-stacked with QUIC on the same host:port.
	tcpTLSListener net.Listener
	http2Server    *http.Server
	udpProxy       *cudprelay.Proxy
	ready          atomic.Bool
	closing        atomic.Bool
	startErr       server.StartErrorStore
	dialer         net.Dialer
	// singServerTLS holds sing-box inbound TLS lifecycle (ACME, cert reload); closed with the endpoint.
	singServerTLS btls.ServerConfig
}

func NewServerEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MasqueEndpointOptions) (adapter.Endpoint, error) {
	o := options
	if normalizeRole(o.Role) != option.MasqueRoleServer {
		o.Role = option.MasqueRoleServer
	}
	if err := validateMasqueOptions(o); err != nil {
		return nil, err
	}
	return &ServerEndpoint{
		Adapter: endpoint.NewAdapterWithDialerOptions(C.TypeMasque, tag, []string{N.NetworkTCP, N.NetworkUDP}, o.DialerOptions),
		options: o,
		router:  router,
		logger:  logger,
	}, nil
}

func (e *ServerEndpoint) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if e.server != nil {
		return nil
	}
	// Fresh listen/Serve cycle: clear shutdown marker from a previous Close().
	// Do not reset closing in Close()'s defer — Serve may still be unwinding after Close returns.
	e.closing.Store(false)
	startOutcome, startErr := server.RunMasqueEndpointStart(server.MasqueEndpointStartConfig{
		Ctx:       context.Background(),
		Options:   e.options,
		TCPRelay:  normalizeTCPRelay(e.options.TCPRelay),
		HTTPLayer: normalizeHTTPLayer(e.options.HTTPLayer),
		MuxHost:   e.muxHost(),
		Logger:    e.logger,
		Lifecycle: server.EndpointLifecycleHooks{
			IsClosing: func() bool { return e.closing.Load() },
			OnReadyFalse: func() {
				e.ready.Store(false)
			},
			OnServeError: func(err error) {
				e.startErr.Store(err)
				if e.logger != nil {
					e.logger.Error("masque server stopped: ", err)
				}
			},
		},
	})
	if startErr != nil {
		return startErr
	}
	applied := server.MapMasqueEndpointStartResult(startOutcome)
	e.compiledAuth = applied.CompiledAuth
	e.singServerTLS = applied.SingServerTLS
	e.server = applied.H3Server
	e.packetConn = applied.PacketConn
	e.http2Server = applied.HTTP2Server
	e.tcpTLSListener = applied.TCPTLSListener
	e.startErr.Clear()
	e.ready.Store(true)
	return nil
}

func (e *ServerEndpoint) endpointMuxFields() server.EndpointMuxFields {
	return server.EndpointMuxFields{
		Tag:       e.Tag(),
		Type:      e.Type(),
		Options:   e.options,
		Router:    e.router,
		Logger:    e.logger,
		Dialer:    e.dialer,
		Authorize: e.authorizeRequest,
		Hooks: server.TemplateAuthorityHooks{
			ResolveTemplates: resolveMasqueServerTemplateURLs,
			RelaxAuthority:   masqueServerShouldRelaxTemplateAuthority,
			RequestForParse:  masqueHTTPRequestForTemplateParse,
			AuthorityMatches: masqueRequestAuthorityMatchesTemplate,
		},
		OnUDPProxyCreated: func(p *cudprelay.Proxy) {
			e.udpProxy = p
		},
	}
}

func (e *ServerEndpoint) muxHost() server.MuxHost {
	return server.BuildEndpointMuxHost(e.endpointMuxFields())
}

func (e *ServerEndpoint) IsReady() bool {
	return server.EndpointIsReady(e.lastStartError(), e.ready.Load())
}

func (e *ServerEndpoint) Close() error {
	e.closing.Store(true)
	e.ready.Store(false)
	err := server.CloseMasqueEndpoint(server.MasqueEndpointCloseInput{
		Stack: server.MasqueStack{
			H3Server:       e.server,
			PacketConn:     e.packetConn,
			HTTP2Server:    e.http2Server,
			TCPTLSListener: e.tcpTLSListener,
		},
		UDPProxy:      e.udpProxy,
		SingServerTLS: e.singServerTLS,
	})
	e.udpProxy = nil
	e.singServerTLS = nil
	e.server = nil
	e.packetConn = nil
	e.http2Server = nil
	e.tcpTLSListener = nil
	return err
}

func (e *ServerEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return server.DialEndpointTCP(ctx, e.dialer, e.lastStartError(), network, destination)
}

func (e *ServerEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return server.ListenEndpointPacket(e.lastStartError())
}

func (e *ServerEndpoint) authorizeRequest(r *http.Request) bool {
	return server.AuthorizeMasqueRequest(r, &e.compiledAuth, e.options, e.server != nil)
}

func (e *ServerEndpoint) lastStartError() error {
	return e.startErr.Load()
}

func (e *ServerEndpoint) handleTCPConnectRequest(w http.ResponseWriter, r *http.Request, tcpTemplate *uritemplate.Template, relaxedTCPAuthority bool) {
	server.HandleTCPConnectRequest(server.BuildTCPConnectHost(e.endpointMuxFields()), w, r, tcpTemplate, relaxedTCPAuthority)
}

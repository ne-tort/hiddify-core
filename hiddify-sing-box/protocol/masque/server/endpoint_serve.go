package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	mh2 "github.com/sagernet/sing-box/transport/masque/h2"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/net/http2"
)

// MasqueServeHooks reports serve lifecycle events from background goroutines.
type MasqueServeHooks struct {
	IsClosing    func() bool
	OnReadyFalse func()
	OnServeError func(err error)
}

// MasqueStack holds runtime listeners after a successful LaunchMasqueStack.
type MasqueStack struct {
	H3Server       *http3.Server
	PacketConn     net.PacketConn
	HTTP2Server    *http.Server
	TCPTLSListener net.Listener
}

// LaunchMasqueStackConfig drives dual-bind listen and HTTP/3 + HTTP/2 collateral serve.
type LaunchMasqueStackConfig struct {
	Handler           http.Handler
	ListenHost        string
	ListenPort        uint16
	HTTP3TLS          *tls.Config
	CollateralTLS     *tls.Config
	H3QUICConfig       *quic.Config
	CongestionControl  string
	EnableH3Datagrams  bool
	ValidateUDP        func(net.PacketConn) error
	Hooks              MasqueServeHooks
}

// LaunchMasqueStack binds UDP and TCP, starts HTTP/3 and HTTP/2 servers.
func LaunchMasqueStack(cfg LaunchMasqueStackConfig) (*MasqueStack, error) {
	addr := MasqueListenAddr(cfg.ListenHost, cfg.ListenPort)
	h3Srv := &http3.Server{
		Handler:         cfg.Handler,
		TLSConfig:       cfg.HTTP3TLS,
		EnableDatagrams: cfg.EnableH3Datagrams,
		Addr:            addr,
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			h3t.ApplyExternalCongestionControl(c, cfg.CongestionControl)
			h3t.TrackQUICConn("server", c)
			return ctx
		},
	}
	if cfg.H3QUICConfig != nil {
		h3Srv.QUICConfig = cfg.H3QUICConfig
	} else {
		// Synth/lab stacks often omit H3QUICConfig; never fall back to stock MaxIncomingStreams=100.
		h3Srv.QUICConfig = h3t.HTTPServerQUICConfig(cfg.CongestionControl)
	}
	bind, bindErr := DualBindMasqueListeners(DualBindConfig{
		ListenHost:  cfg.ListenHost,
		ListenPort:  cfg.ListenPort,
		ValidateUDP: cfg.ValidateUDP,
	})
	if bindErr != nil {
		return nil, E.Cause(bindErr, "listen masque server")
	}
	packetConn := bind.PacketConn
	tcpRaw := bind.TCPRaw
	if tcpRaw == nil {
		_ = packetConn.Close()
		return nil, E.New("masque server: UDP/TCP dual listen exhausted retries")
	}
	stack := &MasqueStack{
		H3Server:   h3Srv,
		PacketConn: packetConn,
	}
	if cfg.CollateralTLS == nil {
		_ = packetConn.Close()
		return nil, E.New("masque server: missing TLS config for HTTP/2 collateral listener")
	}
	tcpTLS := cfg.CollateralTLS.Clone()
	tcpTLS.NextProtos = []string{"h2", "http/1.1"}
	tcpLn := tls.NewListener(tcpRaw, tcpTLS)
	stack.TCPTLSListener = tcpLn
	http2Srv := &http.Server{
		Handler:           cfg.Handler,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
	}
	if err := http2.ConfigureServer(http2Srv, mh2.BulkHTTP2ServerConfig()); err != nil {
		_ = tcpLn.Close()
		_ = packetConn.Close()
		return nil, E.Cause(err, "configure masque HTTP/2 server (RFC 8441 Extended CONNECT)")
	}
	stack.HTTP2Server = http2Srv
	go serveMasqueHTTP2(http2Srv, tcpLn, cfg.Hooks)
	go serveMasqueHTTP3(h3Srv, packetConn, cfg.Hooks)
	return stack, nil
}

func serveMasqueHTTP2(srv *http.Server, ln net.Listener, hooks MasqueServeHooks) {
	err := srv.Serve(ln)
	if err != nil && !(hooks.IsClosing != nil && hooks.IsClosing() && ExpectedShutdownError(err)) {
		if hooks.OnServeError != nil {
			hooks.OnServeError(err)
		}
	}
	if hooks.OnReadyFalse != nil {
		hooks.OnReadyFalse()
	}
}

func serveMasqueHTTP3(srv *http3.Server, pc net.PacketConn, hooks MasqueServeHooks) {
	err := srv.Serve(pc)
	if err != nil && !(hooks.IsClosing != nil && hooks.IsClosing() && ExpectedShutdownError(err)) {
		if hooks.OnServeError != nil {
			hooks.OnServeError(err)
		}
	}
	if hooks.OnReadyFalse != nil {
		hooks.OnReadyFalse()
	}
}

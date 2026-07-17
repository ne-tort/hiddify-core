package server

// cachebust: reality-accept-survive-2026-07-16

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	btls "github.com/sagernet/sing-box/common/tls"
	masquetls "github.com/sagernet/sing-box/protocol/masque/tls"
	mh2 "github.com/sagernet/sing-box/transport/masque/h2"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
	"github.com/sagernet/sing-box/transport/masque/netutil"
	"github.com/sagernet/sing-box/transport/masque/stream/relay"
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
// RealityServer set (H2-only): TCP listener via aTLS.NewListener; no UDP/HTTP3.
type LaunchMasqueStackConfig struct {
	Handler           http.Handler
	ListenHost        string
	ListenPort        uint16
	HTTP3TLS          *tls.Config
	CollateralTLS     *tls.Config
	RealityServer     btls.ServerConfig
	H3QUICConfig      *quic.Config
	CongestionControl string
	EnableH3Datagrams bool
	// H2Tuning overrides baked H2 defaults (SETTINGS / flush / pipe / download relay).
	H2Tuning mh2.Tuning
	ValidateUDP       func(net.PacketConn) error
	Hooks             MasqueServeHooks
}

// LaunchMasqueStack binds UDP and TCP, starts HTTP/3 and HTTP/2 servers.
// Reality H2-only binds TCP only.
func LaunchMasqueStack(cfg LaunchMasqueStackConfig) (*MasqueStack, error) {
	if cfg.RealityServer != nil {
		return launchMasqueH2RealityStack(cfg)
	}
	return launchMasqueDualStack(cfg)
}

func launchMasqueH2RealityStack(cfg LaunchMasqueStackConfig) (*MasqueStack, error) {
	addr := MasqueListenAddr(cfg.ListenHost, cfg.ListenPort)
	tcpRaw, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, E.Cause(err, "listen masque Reality H2 TCP")
	}
	if len(cfg.RealityServer.NextProtos()) == 0 {
		cfg.RealityServer.SetNextProtos([]string{"h2", "http/1.1"})
	}
	// Expose raw TCP under the Reality wrapper so Shutdown can Close the listen
	// socket; handshake runs asynchronously in serveMasqueHTTP2Reality.
	tcpLn := &masqueRealityTLSListener{
		Listener: &masqueTunedTCPListener{Listener: tcpRaw},
		cfg:      cfg.RealityServer,
	}
	h2srv := mh2.BulkHTTP2ServerConfigResolved(mh2.Resolve(cfg.H2Tuning))
	applyH2ServerDownloadPolicy(cfg)
	http1Base := &http.Server{
		Handler:           cfg.Handler,
		ReadHeaderTimeout: 30 * time.Second,
	}
	stack := &MasqueStack{
		HTTP2Server:    http1Base,
		TCPTLSListener: tcpLn,
	}
	go serveMasqueHTTP2Reality(h2srv, http1Base, tcpLn, cfg.Hooks)
	return stack, nil
}

// masqueRealityTLSListener wraps the TCP listen socket for Shutdown/typing.
// Accept is unused by serveMasqueHTTP2Reality (async handshake path); kept for
// interface completeness and any caller that dials through net.Listener directly.
type masqueRealityTLSListener struct {
	net.Listener
	cfg btls.ServerConfig
}

func (l *masqueRealityTLSListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		tlsConn, hsErr := btls.ServerHandshake(context.Background(), c, l.cfg)
		if hsErr != nil {
			_ = c.Close()
			continue
		}
		return tlsConn, nil
	}
}

// RealityAcceptAsyncGuard stays in .rodata for deploy verify (`strings /app/sui`).
// Do not fold to a blank `_ = const` — the compiler eliminates that.
var RealityAcceptAsyncGuard = "scanner storms cannot stall"

// serveMasqueHTTP2Reality Accepts raw TCP and handshakes Reality off the Accept
// path so scanner storms cannot stall/kill the listener.
func serveMasqueHTTP2Reality(h2s *http2.Server, base *http.Server, ln net.Listener, hooks MasqueServeHooks) {
	raw := ln
	if rl, ok := ln.(*masqueRealityTLSListener); ok {
		raw = rl.Listener
	}
	var realityCfg btls.ServerConfig
	if rl, ok := ln.(*masqueRealityTLSListener); ok {
		realityCfg = rl.cfg
	}
	for {
		c, err := raw.Accept()
		if err != nil {
			if hooks.IsClosing != nil && hooks.IsClosing() && ExpectedShutdownError(err) {
				break
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			if hooks.OnServeError != nil {
				hooks.OnServeError(err)
			}
			break
		}
		go func(conn net.Conn) {
			defer conn.Close()
			var tlsConn net.Conn = conn
			if realityCfg != nil {
				hc, hsErr := btls.ServerHandshake(context.Background(), conn, realityCfg)
				if hsErr != nil {
					// Probes: "REALITY: processed invalid connection" etc. — ignore.
					runtime.KeepAlive(RealityAcceptAsyncGuard)
					return
				}
				tlsConn = hc
			}
			netutil.TrackTCPUnderlay("h2-server", tlsConn)
			h2s.ServeConn(tlsConn, &http2.ServeConnOpts{
				BaseConfig: base,
				Handler:    base.Handler,
			})
		}(c)
	}
	if hooks.OnReadyFalse != nil {
		hooks.OnReadyFalse()
	}
}

func launchMasqueDualStack(cfg LaunchMasqueStackConfig) (*MasqueStack, error) {
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
	tcpALPN, alpnErr := masquetls.ApplyServerTCPCollateralALPN(tcpTLS.NextProtos)
	if alpnErr != nil {
		_ = packetConn.Close()
		_ = tcpRaw.Close()
		return nil, E.Cause(alpnErr, "masque server TCP ALPN")
	}
	tcpTLS.NextProtos = tcpALPN
	// Client: MasqueTCPDialerControl / TuneMasqueTCPSocketBuffers before handshake; server Accept
	// matches SNDBUF + Nagle + CC pin. Never SO_RCVBUF on H2 TLS underlay (Linux RWND lock).
	// TrackTCPUnderlay runs post-TLS so server dumps see live retrans (not pre-handshake zombies).
	tcpLn := &masqueTrackedTLSListener{
		Listener: tls.NewListener(&masqueTunedTCPListener{Listener: tcpRaw}, tcpTLS),
		role:     "h2-server",
	}
	stack.TCPTLSListener = tcpLn
	http2Srv := &http.Server{
		Handler:           cfg.Handler,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
	}
	if err := http2.ConfigureServer(http2Srv, mh2.BulkHTTP2ServerConfigResolved(mh2.Resolve(cfg.H2Tuning))); err != nil {
		_ = tcpLn.Close()
		_ = packetConn.Close()
		return nil, E.Cause(err, "configure masque HTTP/2 server (RFC 8441 Extended CONNECT)")
	}
	applyH2ServerDownloadPolicy(cfg)
	stack.HTTP2Server = http2Srv
	go serveMasqueHTTP2(http2Srv, tcpLn, cfg.Hooks)
	go serveMasqueHTTP3(h3Srv, packetConn, cfg.Hooks)
	return stack, nil
}

func applyH2ServerDownloadPolicy(cfg LaunchMasqueStackConfig) {
	p := mh2.Resolve(cfg.H2Tuning)
	relay.ApplyH2DownloadPolicy(relay.H2DownloadPolicy{
		BufferBytes:   p.DownloadBufferBytes,
		FillWait:      p.DownloadFillWait,
		FlushMinBytes: p.DownloadFlushMinBytes,
		FillMaxWall:   p.DownloadFillMaxWall,
	})
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

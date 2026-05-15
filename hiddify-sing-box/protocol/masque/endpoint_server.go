package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dunglas/httpsfv"
	connectip "github.com/quic-go/connect-ip-go"
	qmasque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/dialer"
	btls "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	TM "github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/yosida95/uritemplate/v3"
)

// connectIPServerParseDropTotal counts inbound CONNECT-IP packets dropped at the
// server IP parse boundary (non-fatal; read continues).
var connectIPServerParseDropTotal atomic.Uint64

// masqueRelayTCPCopyBufLen is larger than io.Copy's default (32 KiB) to cut syscall /
// framing overhead on CONNECT-stream bulk relay (H2/H3 response body ↔ target TCP).
const masqueRelayTCPCopyBufLen = 512 * 1024

// masqueRelayTCPKernelBuf is a best-effort SO_RCVBUF/SO_SNDBUF for the onward TCP
// dial to the MASQUE template target (kernel caps still apply).
const masqueRelayTCPKernelBuf = 4 << 20


var masqueRelayTCPCopyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, masqueRelayTCPCopyBufLen)
		return &b
	},
}

func relayCopyBuffered(dst io.Writer, src io.Reader) (int64, error) {
	bp := masqueRelayTCPCopyBufPool.Get().(*[]byte)
	defer masqueRelayTCPCopyBufPool.Put(bp)
	return io.CopyBuffer(dst, src, *bp)
}

func tuneMasqueRelayTCPOutbound(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(masqueRelayTCPKernelBuf)
		_ = tc.SetWriteBuffer(masqueRelayTCPKernelBuf)
	}
}

// ConnectIPServerParseDropTotal exposes the parse-drop counter for tests/ops.
func ConnectIPServerParseDropTotal() uint64 {
	return connectIPServerParseDropTotal.Load()
}

func connectIPRequestErrorHTTPStatus(err error) int {
	var perr *connectip.RequestParseError
	if errors.As(err, &perr) {
		return perr.HTTPStatus
	}
	return http.StatusBadRequest
}

func connectIPRequestErrorClass(status int) TM.ErrorClass {
	switch status {
	case http.StatusBadRequest, http.StatusNotImplemented:
		return TM.ErrorClassCapability
	default:
		return TM.ErrorClassUnknown
	}
}

func connectIPRouteAdvertiseErrorClass(err error) TM.ErrorClass {
	if err == nil {
		return TM.ErrorClassUnknown
	}
	if errors.Is(err, net.ErrClosed) {
		return TM.ErrorClassLifecycle
	}
	if errors.Is(err, connectip.ErrInvalidRouteAdvertisement) {
		return TM.ErrorClassCapability
	}
	return TM.ErrorClassTransport
}

// ServerEndpoint is the MASQUE server (CONNECT-UDP / CONNECT-IP / CONNECT-stream over HTTP/3 + HTTP/2).
type ServerEndpoint struct {
	endpoint.Adapter
	options      option.MasqueEndpointOptions
	compiledAuth *compiledMasqueServerAuth
	router       adapter.Router
	logger       log.ContextLogger
	server       *http3.Server
	packetConn   net.PacketConn
	// tcpTLSListener is the TLS listener (HTTP/2 ALPN) dual-stacked with QUIC on the same host:port.
	tcpTLSListener net.Listener
	http2Server    *http.Server
	udpProxy       *qmasque.Proxy
	ready          atomic.Bool
	closing        atomic.Bool
	startErr       atomic.Value
	dialer         net.Dialer
	// singServerTLS holds sing-box inbound TLS lifecycle (ACME, cert reload); closed with the endpoint.
	singServerTLS btls.ServerConfig
}

type startErrorState struct {
	err error
}

func NewServerEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MasqueEndpointOptions) (adapter.Endpoint, error) {
	o := options
	if normalizeMode(o.Mode) != option.MasqueModeServer {
		o.Mode = option.MasqueModeServer
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
	ctx := context.Background()
	inTLS, err := prepareMasqueServerInboundTLS(e.options.InboundTLS, normalizeHTTPLayer(e.options.HTTPLayer))
	if err != nil {
		return err
	}
	srvCfg, err := btls.NewServerWithOptions(btls.ServerOptions{Context: ctx, Logger: e.logger, Options: *inTLS})
	if err != nil {
		return E.Cause(err, "masque server tls")
	}
	if srvCfg == nil {
		return E.New("masque server: tls config is nil")
	}
	if err := srvCfg.Start(); err != nil {
		return E.Cause(err, "masque server tls start")
	}
	e.singServerTLS = srvCfg
	baseTLS, err := srvCfg.STDConfig()
	if err != nil {
		_ = srvCfg.Close()
		e.singServerTLS = nil
		return E.Cause(err, "masque server tls std config")
	}
	if baseTLS == nil {
		_ = srvCfg.Close()
		e.singServerTLS = nil
		return E.New("masque server: tls std config is nil")
	}
	compiled, compileErr := compileMasqueServerAuth(e.options)
	if compileErr != nil {
		_ = srvCfg.Close()
		e.singServerTLS = nil
		return compileErr
	}
	e.compiledAuth = compiled

	udpTemplateRaw, ipTemplateRaw, tcpTemplateRaw := resolveMasqueServerTemplateURLs(e.options)
	udpTemplate, err := uritemplate.New(udpTemplateRaw)
	if err != nil {
		return E.Cause(err, "invalid server UDP template")
	}
	ipTemplate, err := uritemplate.New(ipTemplateRaw)
	if err != nil {
		return E.Cause(err, "invalid server IP template")
	}
	tcpTemplate, err := uritemplate.New(tcpTemplateRaw)
	if err != nil {
		return E.Cause(err, "invalid server TCP template")
	}
	udpPath := sanitizeTemplatePathForHTTPMux(pathFromTemplate(udpTemplateRaw))
	ipPath := sanitizeTemplatePathForHTTPMux(pathFromTemplate(ipTemplateRaw))
	tcpPath := sanitizeTemplatePathForHTTPMux(pathFromTemplate(tcpTemplateRaw))
	udpProxy := &qmasque.Proxy{}
	e.udpProxy = udpProxy
	ipProxy := &connectip.Proxy{}
	mux := http.NewServeMux()
	mux.HandleFunc(udpPath, func(w http.ResponseWriter, r *http.Request) {
		if !e.authorizeRequest(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		parseR := masqueHTTPRequestForTemplateParse(r, udpTemplate, masqueServerShouldRelaxTemplateAuthority(e.options, masqueTemplateFieldUDP))
		req, err := qmasque.ParseRequest(parseR, udpTemplate)
		if err != nil {
			var perr *qmasque.RequestParseError
			if errors.As(err, &perr) {
				w.WriteHeader(perr.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		e.handleMasqueConnectUDP(w, r, req, udpProxy)
	})
	mux.HandleFunc(ipPath, func(w http.ResponseWriter, r *http.Request) {
		e.logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip request method=%s remote=%s uri=%s", r.Method, r.RemoteAddr, r.URL.String()))
		if !e.authorizeRequest(r) {
			e.logger.DebugContext(r.Context(), "masque connect-ip auth denied status=401")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		parseR := masqueHTTPRequestForTemplateParse(r, ipTemplate, masqueServerShouldRelaxTemplateAuthority(e.options, masqueTemplateFieldIP))
		req, err := connectip.ParseRequest(parseR, ipTemplate)
		if err != nil {
			status := connectIPRequestErrorHTTPStatus(err)
			e.logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip parse denied status=%d error_class=%s err=%v", status, connectIPRequestErrorClass(status), err))
			w.WriteHeader(status)
			return
		}
		conn, err := ipProxy.Proxy(w, r, req)
		if err != nil {
			e.logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip proxy failed status=502 err=%v", err))
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		routeCtx, cancelRoute := context.WithTimeout(r.Context(), 2*time.Second)
		assignErr := conn.AssignAddresses(routeCtx, []netip.Prefix{
			netip.MustParsePrefix("198.18.0.1/32"),
			netip.MustParsePrefix("fd00::1/128"),
		})
		if assignErr != nil {
			cancelRoute()
			e.logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip address assign failed status=502 err=%v", assignErr))
			_ = conn.Close()
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		routeErr := conn.AdvertiseRoute(routeCtx, []connectip.IPRoute{
			{StartIP: netip.IPv4Unspecified(), EndIP: netip.MustParseAddr("255.255.255.255"), IPProtocol: 0},
			{StartIP: netip.IPv6Unspecified(), EndIP: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), IPProtocol: 0},
		})
		cancelRoute()
		if routeErr != nil {
			e.logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip route advertise failed status=502 error_class=%s err=%v", connectIPRouteAdvertiseErrorClass(routeErr), routeErr))
			_ = conn.Close()
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		e.logger.DebugContext(r.Context(), "masque connect-ip route ready status=200")
		packetConn := &connectIPNetPacketConn{conn: conn}
		var metadata adapter.InboundContext
		metadata.Inbound = e.Tag()
		metadata.InboundType = e.Type()
		metadata.Source = M.ParseSocksaddr(r.RemoteAddr)
		metadata.Destination = M.Socksaddr{}
		metadata.User = strings.TrimSpace(r.RemoteAddr)
		e.logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip route dispatch router_type=%T destination=dynamic", e.router))
		// TUN-only hard switch: CONNECT-IP runs as packet-plane forwarding only.
		// Keep all traffic on RoutePacketConnectionEx path and avoid TCP-special bridge.
		routeMasqueConnectIPBlocked(e.router, r.Context(), packetConn, metadata, e.logger, e.options)
	})
	tcpRelaxedAuthority := masqueServerShouldRelaxTemplateAuthority(e.options, masqueTemplateFieldTCP)
	mux.HandleFunc(tcpPath, func(w http.ResponseWriter, r *http.Request) {
		e.handleTCPConnectRequest(w, r, tcpTemplate, tcpRelaxedAuthority)
	})
	listenHost := strings.TrimSpace(e.options.Listen)
	if listenHost == "" {
		listenHost = "0.0.0.0"
	}
	addr := net.JoinHostPort(listenHost, strconv.Itoa(int(e.options.ListenPort)))
	e.server = &http3.Server{
		Addr:            addr,
		Handler:         mux,
		TLSConfig:       http3.ConfigureTLSConfig(baseTLS),
		EnableDatagrams: true,
		QUICConfig:      TM.MasqueHTTPServerQUICConfig(),
	}
	// Align UDP/QUIC listener port with collateral TCP+H2 TLS must succeed for both transports.
	// Windows (and similar) may reserve wide excluded ephemeral ranges where UDP bind succeeds but
	// sibling TCP bind on the same port returns WSAEACCESS / "access permissions"; retries must be
	// generous enough that listen_port:0 converges outside those ranges without user tuning.
	const masqueDynPortBindAttempts = 512
	ephemeralPorts := int(e.options.ListenPort) == 0
	maxAttempts := 1
	if ephemeralPorts {
		maxAttempts = masqueDynPortBindAttempts
	}
	var packetConn net.PacketConn
	var tcpRaw net.Listener
	var lastTCPListenErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		pc, udpErr := net.ListenPacket("udp", addr)
		if udpErr != nil {
			return E.Cause(udpErr, "listen udp for masque server")
		}
		if err := TM.ValidateQUICTransportPacketConn(pc, "server_http3_listen"); err != nil {
			_ = pc.Close()
			return E.Cause(err, "validate quic transport packetconn")
		}
		us := pc.LocalAddr()
		uaddr, uok := us.(*net.UDPAddr)
		if !uok || uaddr == nil {
			_ = pc.Close()
			e.server = nil
			return E.New("masque server: UDP listener has unexpected address type ", us)
		}
		tcpBind := net.JoinHostPort(listenHost, strconv.Itoa(uaddr.Port))
		tr, tcpErr := net.Listen("tcp", tcpBind)
		if tcpErr == nil {
			packetConn = pc
			tcpRaw = tr
			break
		}
		_ = pc.Close()
		lastTCPListenErr = tcpErr
		if ephemeralPorts && masqueTCPBindFailureRetryable(tcpErr) {
			continue
		}
		e.server = nil
		return E.Cause(tcpErr, "listen tcp for masque server (http2 extended connect)")
	}
	if packetConn == nil || tcpRaw == nil {
		e.server = nil
		err := lastTCPListenErr
		if err == nil {
			err = errors.New("masque server: UDP/TCP dual listen exhausted retries")
		}
		return E.Cause(err, "listen tcp for masque server (http2 extended connect)")
	}
	e.packetConn = packetConn

	tcpTLS := baseTLS.Clone()
	tcpTLS.NextProtos = []string{"h2", "http/1.1"}
	tcpLn := tls.NewListener(tcpRaw, tcpTLS)
	e.tcpTLSListener = tcpLn
	http2Srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
	}
	if err := http2.ConfigureServer(http2Srv, &http2.Server{}); err != nil {
		return E.Cause(err, "configure masque HTTP/2 server (RFC 8441 Extended CONNECT)")
	}
	e.http2Server = http2Srv
	go func() {
		err := http2Srv.Serve(tcpLn)
		if err != nil && !(e.closing.Load() && isExpectedServerShutdownError(err)) {
			e.startErr.Store(startErrorState{err: err})
			if e.logger != nil {
				e.logger.Error("masque HTTP/2 server stopped: ", err)
			}
		}
		e.ready.Store(false)
	}()

	server := e.server
	go func() {
		err := server.Serve(packetConn)
		if err != nil && !(e.closing.Load() && isExpectedServerShutdownError(err)) {
			e.startErr.Store(startErrorState{err: err})
			if e.logger != nil {
				e.logger.Error("masque server stopped: ", err)
			}
		}
		e.ready.Store(false)
	}()
	e.startErr.Store(startErrorState{})
	e.ready.Store(true)
	return nil
}

func routePacketConnectionExBypassTunnelWrapper(router adapter.Router, ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc, routeLog log.ContextLogger) {
	if router != nil {
		router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	lg := routeLog
	if lg == nil {
		lg = log.NewNOPFactory().NewLogger("masque-connect-ip-fallback")
	}
	// Standalone MASQUE server (e.g. tests) may omit Router; use the default dial stack without
	// domain-resolution extras (avoids DNSTransportManager from service context).
	fallbackCtx := service.ContextWithDefaultRegistry(ctx)
	nd, err := dialer.NewWithOptions(dialer.Options{
		Context:        fallbackCtx,
		Options:        option.DialerOptions{},
		RemoteIsDomain: false,
		DirectOutbound: true,
	})
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	cm := route.NewConnectionManager(lg)
	cm.NewPacketConnection(ctx, nd, conn, metadata, onClose)
}

// masqueConnectIPDataplaneContext returns a context for CONNECT-IP packet-plane work that does not
// propagate cancellation from the inbound HTTP request. sing-box Router forwards the same ctx into
// matchRule and outbound packet handlers; req.Context may cancel independently of relay lifetime.
func masqueConnectIPDataplaneContext(reqCtx context.Context) context.Context {
	return context.WithoutCancel(reqCtx)
}

// routeMasqueConnectIPBlocked keeps this HTTP handler alive until the CONNECT-IP packet-plane
// relay ends. On HTTP/3 the stream is hijacked via http3.HTTPStreamer inside connect-ip Proxy,
// so ending the handler does not close the QUIC stream. On HTTP/2 Extended CONNECT there is no
// hijack; if the handler returned immediately, net/http would finalize the response and tear down
// the CONNECT stream while RoutePacketConnectionEx goroutines were still running.
func routeMasqueConnectIPBlocked(router adapter.Router, reqCtx context.Context, packetConn *connectIPNetPacketConn, metadata adapter.InboundContext, logger log.ContextLogger, opts option.MasqueEndpointOptions) {
	done := make(chan struct{})
	var once sync.Once
	notify := func() { once.Do(func() { close(done) }) }
	onClose := func(err error) {
		if err != nil && !errors.Is(err, context.Canceled) && logger != nil {
			logger.DebugContext(reqCtx, fmt.Sprintf("masque connect-ip route closed err=%v", err))
		}
		_ = packetConn.Close()
		notify()
	}
	if router == nil {
		fwdCtx := masqueConnectIPDataplaneContext(reqCtx)
		go func() {
			err := TM.RunConnectIPTCPPacketPlaneForwarder(fwdCtx, packetConn.conn, TM.ConnectIPTCPForwarderOptions{
				AllowPrivateTargets: opts.AllowPrivateTargets,
				AllowedTargetPorts:  opts.AllowedTargetPorts,
				BlockedTargetPorts:  opts.BlockedTargetPorts,
			})
			onClose(err)
		}()
		<-done
		return
	}
	// Match router==nil branch: dataplane must not inherit HTTP request cancellation.
	// Router.RoutePacketConnectionEx forwards this ctx to matchRule / outbound packet handlers (see route/route.go).
	routeCtx := masqueConnectIPDataplaneContext(reqCtx)
	routePacketConnectionExBypassTunnelWrapper(router, routeCtx, packetConn, metadata, onClose, logger)
	<-done
}

func pathFromTemplate(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "/"
	}
	path := u.Path
	if q := strings.Index(path, "?"); q >= 0 {
		path = path[:q]
	}
	if path == "" {
		return "/"
	}
	return path
}

// sanitizeTemplatePathForHTTPMux maps URI-template path segments to patterns valid for
// net/http.ServeMux (Go 1.22+): wildcard names must be simple identifiers; "{+target_host}"
// from RFC 6570 reserved expansion is not accepted as a mux wildcard name.
func sanitizeTemplatePathForHTTPMux(path string) string {
	path = strings.ReplaceAll(path, "{+target_host*}", "{target_host*}")
	path = strings.ReplaceAll(path, "{+target_host:", "{target_host:")
	path = strings.ReplaceAll(path, "{+target_host}", "{target_host}")
	return path
}

func (e *ServerEndpoint) IsReady() bool {
	if e.lastStartError() != nil {
		return false
	}
	return e.ready.Load()
}

func (e *ServerEndpoint) Close() error {
	e.closing.Store(true)
	e.ready.Store(false)
	if e.udpProxy != nil {
		e.udpProxy.Close()
		e.udpProxy = nil
	}
	if e.http2Server != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		_ = e.http2Server.Shutdown(shutdownCtx)
		cancel()
		e.http2Server = nil
	}
	if e.tcpTLSListener != nil {
		_ = e.tcpTLSListener.Close()
		e.tcpTLSListener = nil
	}
	if e.singServerTLS != nil {
		_ = e.singServerTLS.Close()
		e.singServerTLS = nil
	}
	if e.server != nil {
		_ = e.server.Close()
		e.server = nil
	}
	var err error
	if e.packetConn != nil {
		err = e.packetConn.Close()
		e.packetConn = nil
	}
	return err
}

func (e *ServerEndpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if err := e.lastStartError(); err != nil {
		return nil, E.Cause(err, "masque server startup failed")
	}
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, E.New("unsupported network for server endpoint: ", network)
	}
	if destination.IsFqdn() {
		return e.dialer.DialContext(ctx, network, net.JoinHostPort(destination.Fqdn, strconv.Itoa(int(destination.Port))))
	}
	if destination.Addr.IsValid() {
		return e.dialer.DialContext(ctx, network, net.JoinHostPort(destination.Addr.String(), strconv.Itoa(int(destination.Port))))
	}
	return nil, errors.Join(TM.ErrCapability, E.New("invalid destination"))
}

func (e *ServerEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := e.lastStartError(); err != nil {
		return nil, E.Cause(err, "masque server startup failed")
	}
	return net.ListenPacket("udp", "")
}

func (e *ServerEndpoint) authorizeRequest(r *http.Request) bool {
	a := e.compiledAuth
	// Unit tests call authorizeRequest/handleTCPConnectRequest without Start(); compile from options.
	if a == nil && e.server == nil {
		var err error
		a, err = compileMasqueServerAuth(e.options)
		if err != nil || a == nil {
			return true
		}
	}
	if a == nil {
		return true
	}
	return a.AuthorizeRequest(r)
}

const masqueRequestProtocolConnectUDP = "connect-udp"

// extendedMasqueTunnelProtocol returns the CONNECT tunnel pseudo-protocol (:protocol header on H2 or Proto on H3).
func extendedMasqueTunnelProtocol(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v := strings.TrimSpace(r.Header.Get(":protocol")); v != "" {
		return v
	}
	p := strings.TrimSpace(r.Proto)
	if p == "" {
		return ""
	}
	if len(p) >= 5 && strings.EqualFold(p[:5], "http/") {
		return ""
	}
	return p
}

func dnsErrorToMasqueProxyStatus(proxyStatus *httpsfv.Item, dnsError *net.DNSError) {
	if dnsError.Timeout() {
		proxyStatus.Params.Add("error", "dns_timeout")
		return
	}
	proxyStatus.Params.Add("error", "dns_error")
	if dnsError.IsNotFound {
		proxyStatus.Params.Add("rcode", "Negative response")
	} else {
		proxyStatus.Params.Add("rcode", "SERVFAIL")
	}
}

func masqueUDPResolveDialToHTTPStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return http.StatusGatewayTimeout
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return http.StatusBadGateway
	}
	var addrErr *net.AddrError
	var parseError *net.ParseError
	if errors.As(err, &addrErr) || errors.As(err, &parseError) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func (e *ServerEndpoint) handleMasqueConnectUDP(w http.ResponseWriter, r *http.Request, parsed *qmasque.Request, udpProxy *qmasque.Proxy) {
	if _, ok := w.(http3.HTTPStreamer); ok {
		if err := udpProxy.Proxy(w, parsed); err != nil {
			w.WriteHeader(http.StatusBadGateway)
		}
		return
	}
	if !strings.EqualFold(extendedMasqueTunnelProtocol(r), masqueRequestProtocolConnectUDP) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	proxyStatus := httpsfv.NewItem(parsed.Host)
	writeProxyStatus := func(err error) error {
		if err != nil {
			proxyStatus.Params.Add("details", err.Error())
		}
		val, marshalErr := httpsfv.Marshal(proxyStatus)
		if marshalErr != nil {
			return marshalErr
		}
		w.Header().Add("Proxy-Status", val)
		return err
	}

	addr, err := net.ResolveUDPAddr("udp", parsed.Target)
	if err != nil {
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) {
			dnsErrorToMasqueProxyStatus(&proxyStatus, dnsError)
		}
		_ = writeProxyStatus(err)
		w.WriteHeader(masqueUDPResolveDialToHTTPStatus(err))
		return
	}
	proxyStatus.Params.Add("next-hop", addr.String())

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		proxyStatus.Params.Add("error", "destination_ip_unroutable")
		_ = writeProxyStatus(err)
		w.WriteHeader(masqueUDPResolveDialToHTTPStatus(err))
		return
	}

	if err := writeProxyStatus(nil); err != nil {
		_ = conn.Close()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set(http3.CapsuleProtocolHeader, TM.CapsuleProtocolHeaderValueH2())
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	_ = TM.ServeH2ConnectUDP(w, r, conn)
}

func (e *ServerEndpoint) lastStartError() error {
	value := e.startErr.Load()
	if value == nil {
		return nil
	}
	state, ok := value.(startErrorState)
	if !ok {
		return nil
	}
	return state.err
}

// masqueTCPBindFailureRetryable matches OS-level bind denials where the kernel picked an ephemeral
// UDP port that cannot be shared with a collocated TCP listener (observed on Windows excluded ranges).
func masqueTCPBindFailureRetryable(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "forbidden") ||
		strings.Contains(text, "permission denied") ||
		strings.Contains(text, "access is denied") ||
		strings.Contains(text, "wsaeaccess")
}

func isExpectedServerShutdownError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) || errors.Is(err, quic.ErrServerClosed) {
		return true
	}
	text := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(text, "use of closed network connection") ||
		strings.Contains(text, "server closed")
}

func (e *ServerEndpoint) handleTCPConnectRequest(w http.ResponseWriter, r *http.Request, tcpTemplate *uritemplate.Template, relaxedTCPAuthority bool) {
	debugf := func(format string, args ...any) {
		if e.logger == nil {
			return
		}
		e.logger.DebugContext(r.Context(), fmt.Sprintf(format, args...))
	}
	if r.Method != http.MethodConnect {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	debugf("masque tcp connect request method=%s remote=%s uri=%s", r.Method, r.RemoteAddr, r.URL.String())
	if !e.authorizeRequest(r) {
		debugf("masque tcp connect auth denied status=401")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// RFC 8441 Extended CONNECT over HTTP/2 sets :protocol. Our CONNECT-stream client uses HTTP/2
	// (see transport/masque/h2_connect_stream.go). HTTP/3 CONNECT-stream peers typically omit
	// :protocol while Proto carries HTTP/3 — treat empty header as compat. Reject misuse such
	// as connect-udp/connect-ip targeting the tcp template early (400), before policy/dial work.
	if p := strings.TrimSpace(r.Header.Get(":protocol")); p != "" && !strings.EqualFold(p, "HTTP/2") {
		debugf("masque tcp connect denied status=400 error_class=bad_extended_protocol proto=%q", p)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	targetHost, targetPort, parseErr := parseTCPTargetFromRequest(r, tcpTemplate, relaxedTCPAuthority)
	if parseErr != nil {
		debugf("masque tcp connect parse denied status=400 error_class=misconfig err=%v", parseErr)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	resolvedHost, allowErr := resolveTCPTargetForDial(r.Context(), targetHost, e.options.AllowPrivateTargets)
	if allowErr != nil {
		debugf("masque tcp connect policy denied host=%s port=%s status=403 error_class=policy err=%v", targetHost, targetPort, allowErr)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !allowTCPPort(targetPort, e.options.AllowedTargetPorts, e.options.BlockedTargetPorts) {
		debugf("masque tcp connect policy denied host=%s port=%s status=403 error_class=policy err=port_policy_denied", targetHost, targetPort)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	debugf("masque tcp connect dial start host=%s resolved_host=%s port=%s", targetHost, resolvedHost, targetPort)
	targetConn, dialErr := e.dialer.DialContext(r.Context(), "tcp", net.JoinHostPort(resolvedHost, targetPort))
	if dialErr != nil {
		debugf("masque tcp connect dial failed host=%s resolved_host=%s port=%s status=502 error_class=%s err=%v", targetHost, resolvedHost, targetPort, TM.ClassifyError(errors.Join(TM.ErrTCPDial, dialErr)), dialErr)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	tuneMasqueRelayTCPOutbound(targetConn)
	defer targetConn.Close()
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}
	debugf("masque tcp connect accepted host=%s resolved_host=%s port=%s status=200", targetHost, resolvedHost, targetPort)
	relayErr := relayTCPBidirectional(r.Context(), targetConn, r.Body, w)
	if relayErr != nil && !errors.Is(relayErr, io.EOF) && !errors.Is(relayErr, context.Canceled) {
		debugf("masque tcp relay finished host=%s resolved_host=%s port=%s status=relay_error error_class=relay_io err=%v", targetHost, resolvedHost, targetPort, relayErr)
		return
	}
	debugf("masque tcp relay finished host=%s resolved_host=%s port=%s status=ok", targetHost, resolvedHost, targetPort)
}

func resolveTCPTargetForDial(ctx context.Context, host string, allowPrivateTargets bool) (string, error) {
	if allowPrivateTargets {
		return strings.Trim(strings.TrimSpace(host), "[]"), nil
	}
	trimmedHost := strings.Trim(strings.TrimSpace(host), "[]")
	lowerHost := strings.ToLower(trimmedHost)
	if lowerHost == "" || lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".local") {
		return "", E.New("private target denied")
	}
	addr, err := netip.ParseAddr(trimmedHost)
	if err != nil {
		resolver := net.DefaultResolver
		resolveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		resolved, lookupErr := resolver.LookupNetIP(resolveCtx, "ip", trimmedHost)
		if lookupErr != nil || len(resolved) == 0 {
			return "", E.New("failed to resolve tcp target")
		}
		var chosen string
		for _, rip := range resolved {
			if rip.IsLoopback() || rip.IsPrivate() || rip.IsMulticast() || rip.IsLinkLocalUnicast() || rip.IsLinkLocalMulticast() || rip.IsUnspecified() {
				return "", E.New("private target denied")
			}
			if chosen == "" {
				chosen = rip.String()
			}
		}
		if chosen == "" {
			return "", E.New("failed to select resolved tcp target")
		}
		return chosen, nil
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
		return "", E.New("private target denied")
	}
	return addr.String(), nil
}

func allowTCPPort(portRaw string, allowList []uint16, denyList []uint16) bool {
	port, err := strconv.Atoi(strings.TrimSpace(portRaw))
	if err != nil || port <= 0 || port > 65535 {
		return false
	}
	for _, denied := range denyList {
		if int(denied) == port {
			return false
		}
	}
	if len(allowList) == 0 {
		return true
	}
	for _, allowed := range allowList {
		if int(allowed) == port {
			return true
		}
	}
	return false
}

func relayTCPBidirectional(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, responseWriter io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	uploadErrCh := make(chan error, 1)
	downloadErrCh := make(chan error, 1)
	go func() {
		_, err := relayCopyBuffered(targetConn, reqBody)
		if cw, ok := targetConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		uploadErrCh <- err
	}()
	go func() {
		// Complete partial writes regardless of Flush support — same hazard as Flush-wrapped path.
		var flusher http.Flusher
		if f, ok := responseWriter.(http.Flusher); ok {
			flusher = f
		}
		out := &flushWriter{w: responseWriter, f: flusher}
		defer out.flush()
		_, err := relayCopyBuffered(out, targetConn)
		downloadErrCh <- err
	}()
	select {
	case <-ctx.Done():
		_ = targetConn.Close()
		_ = reqBody.Close()
		uploadErr := <-uploadErrCh
		downloadErr := <-downloadErrCh
		return errors.Join(context.Cause(ctx), uploadErr, downloadErr)
	case uploadErr := <-uploadErrCh:
		if uploadErr != nil && !errors.Is(uploadErr, io.EOF) {
			_ = targetConn.Close()
		}
		downloadErr := <-downloadErrCh
		_ = targetConn.Close()
		_ = reqBody.Close()
		return errors.Join(uploadErr, downloadErr)
	}
}

type flushWriter struct {
	w io.Writer
	// Optional; CONNECT responses often implement http.Flusher for incremental frames.
	f http.Flusher
}

func (w *flushWriter) flush() {
	if w.f != nil {
		w.f.Flush()
	}
}

func (w *flushWriter) Write(p []byte) (int, error) {
	// Underlying ResponseWriter implementations may legally return partial progress
	// with a nil error; io.Copy rejects that (ErrShortWrite). Drain the full slice
	// (parity transport/masque writeAllIOWriter on stream bodies).
	nn := 0
	for nn < len(p) {
		n, err := w.w.Write(p[nn:])
		nn += n
		if err != nil {
			return nn, err
		}
		if n == 0 {
			return nn, io.ErrShortWrite
		}
	}
	// One flush per io.Copy chunk avoids H2/H3 response body fragmentation where the
	// stack performs many short writes (each would otherwise flush and cap throughput).
	if nn > 0 && w.f != nil {
		w.f.Flush()
	}
	return nn, nil
}

type connectIPNetPacketConn struct {
	conn      *connectip.Conn
	deadlines connDeadlines
}

var _ N.PacketConn = (*connectIPNetPacketConn)(nil)

func (c *connectIPNetPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	for {
		n, err := c.conn.ReadPacket(buffer.FreeBytes())
		if err != nil {
			TM.ObserveConnectIPServerReadError(err)
			return M.Socksaddr{}, err
		}
		buffer.Truncate(n)
		destination, payloadStart, payloadEnd, parseErr := parseIPDestinationAndPayload(buffer.Bytes())
		if parseErr != nil {
			connectIPServerParseDropTotal.Add(1)
			buffer.Reset()
			if c.deadlines.readTimeoutExceeded() {
				return M.Socksaddr{}, os.ErrDeadlineExceeded
			}
			continue
		}
		if payloadStart > 0 || payloadEnd < n {
			// Avoid the per-packet memmove of the IPv4/IPv6+UDP payload by
			// shifting the buffer window in place; the caller observes only
			// buffer.Bytes() after Advance/Truncate.
			buffer.Advance(payloadStart)
			buffer.Truncate(payloadEnd - payloadStart)
		}
		TM.ObserveConnectIPServerReadSuccess(n)
		return destination, nil
	}
}

func (c *connectIPNetPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return c.writeOutgoingWithICMPRelay(buffer.Bytes())
}

// Relay PTB/control feedback returned by connect-ip-go (ICMP payload as a full IP packet).
const connectIPMaxICMPRelay = 8

func (c *connectIPNetPacketConn) writeOutgoingWithICMPRelay(packet []byte) error {
	peerPrefixes := c.conn.CurrentPeerPrefixes()
	payload := TM.RewriteConnectIPOutgoingPeerDst(packet, peerPrefixes)
	for i := 0; i < connectIPMaxICMPRelay; i++ {
		if i > 0 {
			payload = TM.RewriteConnectIPOutgoingPeerDst(payload, peerPrefixes)
		}
		icmp, err := c.conn.WritePacket(payload)
		TM.ObserveConnectIPServerWriteIteration(len(payload), len(icmp), err)
		if err != nil {
			return err
		}
		if len(icmp) == 0 {
			return nil
		}
		payload = icmp
	}
	return E.New("connect-ip: ICMP feedback relay exceeded")
}

func (c *connectIPNetPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.deadlines.readTimeoutExceeded() {
		return 0, nil, os.ErrDeadlineExceeded
	}
	for {
		n, err = c.conn.ReadPacket(p)
		if err != nil {
			TM.ObserveConnectIPServerReadError(err)
			return 0, nil, err
		}
		rawN := n
		destination, payloadStart, payloadEnd, parseErr := parseIPDestinationAndPayload(p[:n])
		if parseErr != nil {
			connectIPServerParseDropTotal.Add(1)
			if c.deadlines.readTimeoutExceeded() {
				return 0, nil, os.ErrDeadlineExceeded
			}
			continue
		}
		if payloadStart > 0 || payloadEnd < n {
			payloadLen := payloadEnd - payloadStart
			copy(p[:payloadLen], p[payloadStart:payloadEnd])
			n = payloadLen
		}
		TM.ObserveConnectIPServerReadSuccess(rawN)
		return n, &net.IPAddr{IP: net.IP(destination.Addr.AsSlice())}, nil
	}
}

func (c *connectIPNetPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.deadlines.writeTimeoutExceeded() {
		return 0, os.ErrDeadlineExceeded
	}
	err = c.writeOutgoingWithICMPRelay(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *connectIPNetPacketConn) Close() error { return c.conn.Close() }
func (c *connectIPNetPacketConn) LocalAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4zero}
}
func (c *connectIPNetPacketConn) SetDeadline(t time.Time) error {
	c.deadlines.setDeadline(t)
	return nil
}
func (c *connectIPNetPacketConn) SetReadDeadline(t time.Time) error {
	c.deadlines.setReadDeadline(t)
	return nil
}
func (c *connectIPNetPacketConn) SetWriteDeadline(t time.Time) error {
	c.deadlines.setWriteDeadline(t)
	return nil
}

// connDeadlines stores read/write deadlines as Unix-nanosecond atomics
// (0 = no deadline). Hot ReadFrom/WriteTo paths perform a single
// atomic.Load to check, avoiding per-packet RLock/RUnlock.
type connDeadlines struct {
	read  atomic.Int64
	write atomic.Int64
}

func deadlineNanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func (d *connDeadlines) setDeadline(t time.Time) {
	v := deadlineNanos(t)
	d.read.Store(v)
	d.write.Store(v)
}

func (d *connDeadlines) setReadDeadline(t time.Time) {
	d.read.Store(deadlineNanos(t))
}

func (d *connDeadlines) setWriteDeadline(t time.Time) {
	d.write.Store(deadlineNanos(t))
}

func (d *connDeadlines) readTimeoutExceeded() bool {
	v := d.read.Load()
	return v != 0 && time.Now().UnixNano() > v
}

func (d *connDeadlines) writeTimeoutExceeded() bool {
	v := d.write.Load()
	return v != 0 && time.Now().UnixNano() > v
}

func masqueListenBindsUnspecified(listen string) bool {
	h := strings.TrimSpace(listen)
	if h == "" {
		return true
	}
	hostForParse := stripIPv6BracketsForParse(h)
	if i := strings.IndexByte(hostForParse, '%'); i >= 0 {
		hostForParse = hostForParse[:i]
	}
	if ip := net.ParseIP(hostForParse); ip != nil {
		return ip.IsUnspecified()
	}
	return false
}

func parseTCPTargetFromRequest(r *http.Request, template *uritemplate.Template, relaxedTCPAuthority bool) (string, string, error) {
	if r.Method != http.MethodConnect {
		return "", "", E.New("expected CONNECT request")
	}
	templateURL, err := url.Parse(template.Raw())
	if err != nil {
		return "", "", E.Cause(err, "parse tcp template")
	}
	if templateURL.Host != "" && !masqueRequestAuthorityMatchesTemplate(templateURL.Host, strings.TrimSpace(r.Host), relaxedTCPAuthority) {
		return "", "", E.New("CONNECT authority does not match TCP template host")
	}
	var candidates []string
	appendCandidate := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" {
			candidates = append(candidates, s)
		}
	}
	appendCandidate(r.URL.String())
	if path := strings.TrimSpace(r.URL.Path); path != "" {
		if q := strings.TrimSpace(r.URL.RawQuery); q != "" {
			appendCandidate(path + "?" + q)
		} else {
			appendCandidate(path)
		}
	}
	appendCandidate(r.RequestURI)
	// Parity with connect-ip-go matchTemplateRequestValues: some HTTP/2 stacks surface
	// path-only RequestURI; absolute URI templates need https://authority + normalized path.
	requestURIWithAuthority := ""
	if auth := strings.TrimSpace(r.Host); auth != "" {
		switch requestURI := strings.TrimSpace(r.RequestURI); {
		case requestURI == "":
		case strings.HasPrefix(strings.ToLower(requestURI), "http://"),
			strings.HasPrefix(strings.ToLower(requestURI), "https://"):
			requestURIWithAuthority = requestURI
		default:
			if !strings.HasPrefix(requestURI, "/") {
				requestURI = "/" + requestURI
			}
			scheme := strings.TrimSpace(templateURL.Scheme)
			if scheme == "" {
				scheme = "https"
			}
			requestURIWithAuthority = scheme + "://" + auth + requestURI
		}
	}
	appendCandidate(requestURIWithAuthority)
	if relaxedTCPAuthority && templateURL.Host != "" {
		scheme := strings.TrimSpace(templateURL.Scheme)
		if scheme == "" {
			scheme = "https"
		}
		requestURI := strings.TrimSpace(r.RequestURI)
		switch {
		case requestURI == "":
		case strings.HasPrefix(strings.ToLower(requestURI), "http://"),
			strings.HasPrefix(strings.ToLower(requestURI), "https://"):
		default:
			if !strings.HasPrefix(requestURI, "/") {
				requestURI = "/" + requestURI
			}
			appendCandidate(scheme + "://" + templateURL.Host + requestURI)
		}
		if p := strings.TrimSpace(r.URL.Path); p != "" {
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			appendCandidate(scheme + "://" + templateURL.Host + p)
		}
	}
	var host, port string
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		match := template.Match(candidate)
		host = strings.TrimSpace(match.Get("target_host").String())
		port = strings.TrimSpace(match.Get("target_port").String())
		if host != "" && port != "" {
			break
		}
	}
	if host == "" || port == "" {
		return "", "", E.New("invalid tcp target")
	}
	if parsed, err := strconv.Atoi(port); err != nil || parsed <= 0 || parsed > 65535 {
		return "", "", E.New("invalid tcp target port")
	}
	return host, port, nil
}

func parseIPDestinationAndPayload(packet []byte) (M.Socksaddr, int, int, error) {
	if len(packet) < 1 {
		return M.Socksaddr{}, 0, 0, E.New("invalid empty ip packet")
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return M.Socksaddr{}, 0, 0, E.New("invalid ipv4 packet")
		}
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || len(packet) < ihl {
			return M.Socksaddr{}, 0, 0, E.New("invalid ipv4 header length")
		}
		destination := M.Socksaddr{Addr: netip.AddrFrom4([4]byte(packet[16:20]))}
		protocol := packet[9]
		if (packet[9] == 6 || packet[9] == 17) && len(packet) >= ihl+4 {
			destination.Port = uint16(packet[ihl+2])<<8 | uint16(packet[ihl+3])
		}
		payloadStart, payloadEnd := 0, len(packet)
		if protocol == 17 && len(packet) >= ihl+8 {
			totalLen := int(uint16(packet[2])<<8 | uint16(packet[3]))
			if totalLen <= 0 || totalLen > len(packet) {
				totalLen = len(packet)
			}
			udpLen := int(uint16(packet[ihl+4])<<8 | uint16(packet[ihl+5]))
			payloadStart = ihl + 8
			payloadEnd = totalLen
			if udpLen >= 8 {
				payloadEnd = intMin(payloadEnd, ihl+udpLen)
			}
			if payloadStart > payloadEnd || payloadEnd > len(packet) {
				return M.Socksaddr{}, 0, 0, E.New("invalid ipv4 udp payload")
			}
		}
		return destination, payloadStart, payloadEnd, nil
	case 6:
		if len(packet) < 40 {
			return M.Socksaddr{}, 0, 0, E.New("invalid ipv6 packet")
		}
		destination := M.Socksaddr{Addr: netip.AddrFrom16([16]byte(packet[24:40]))}
		nextHeader, transportOffset, err := ipv6TransportHeaderOffset(packet)
		if err != nil {
			return M.Socksaddr{}, 0, 0, err
		}
		if (nextHeader == 6 || nextHeader == 17) && len(packet) >= transportOffset+4 {
			destination.Port = uint16(packet[transportOffset+2])<<8 | uint16(packet[transportOffset+3])
		}
		payloadStart, payloadEnd := 0, len(packet)
		if nextHeader == 17 && len(packet) >= transportOffset+8 {
			payloadStart = transportOffset + 8
			totalLen := len(packet)
			ipPayloadLen := int(uint16(packet[4])<<8 | uint16(packet[5]))
			if ipPayloadLen > 0 {
				totalLen = intMin(totalLen, 40+ipPayloadLen)
			}
			payloadEnd = totalLen
			udpLen := int(uint16(packet[transportOffset+4])<<8 | uint16(packet[transportOffset+5]))
			if udpLen >= 8 {
				payloadEnd = intMin(payloadEnd, transportOffset+udpLen)
			}
			if payloadStart > payloadEnd || payloadEnd > len(packet) {
				return M.Socksaddr{}, 0, 0, E.New("invalid ipv6 udp payload")
			}
		}
		return destination, payloadStart, payloadEnd, nil
	default:
		return M.Socksaddr{}, 0, 0, E.New("unsupported ip packet version")
	}
}

func ipv6TransportHeaderOffset(packet []byte) (uint8, int, error) {
	nextHeader := packet[6]
	offset := 40
	for {
		switch nextHeader {
		// RFC 8200 extension headers encoded in 8-byte units.
		case 0, 43, 60, 135, 139, 140, 253, 254:
			if len(packet) < offset+2 {
				return 0, 0, E.New("invalid ipv6 extension header")
			}
			headerLen := int(packet[offset+1]+1) * 8
			if headerLen <= 0 || len(packet) < offset+headerLen {
				return 0, 0, E.New("invalid ipv6 extension header length")
			}
			nextHeader = packet[offset]
			offset += headerLen
		case 44:
			if len(packet) < offset+8 {
				return 0, 0, E.New("invalid ipv6 fragment header")
			}
			nextHeader = packet[offset]
			offset += 8
		default:
			return nextHeader, offset, nil
		}
	}
}

func intMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

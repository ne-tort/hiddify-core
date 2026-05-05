package masque

import (
	"context"
	"crypto/subtle"
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

	connectip "github.com/quic-go/connect-ip-go"
	qmasque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	TM "github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/yosida95/uritemplate/v3"
)

// connectIPServerParseDropTotal counts inbound CONNECT-IP packets dropped at the
// server IP parse boundary (non-fatal; read continues).
var connectIPServerParseDropTotal atomic.Uint64

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

type ServerEndpoint struct {
	endpoint.Adapter
	options    option.MasqueEndpointOptions
	router     adapter.Router
	logger     log.ContextLogger
	server     *http3.Server
	packetConn net.PacketConn
	udpProxy   *qmasque.Proxy
	ready      atomic.Bool
	closing    atomic.Bool
	startErr   atomic.Value
	dialer     net.Dialer
}

type startErrorState struct {
	err error
}

func NewServerEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MasqueEndpointOptions) (adapter.Endpoint, error) {
	return &ServerEndpoint{
		Adapter: endpoint.NewAdapterWithDialerOptions(C.TypeMasque, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		options: options,
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
	tlsCert, err := tls.LoadX509KeyPair(e.options.Certificate, e.options.Key)
	if err != nil {
		return E.Cause(err, "load server certificate")
	}
	udpTemplateRaw := strings.TrimSpace(e.options.TemplateUDP)
	if udpTemplateRaw == "" {
		udpTemplateRaw = "https://masque.local/masque/udp/{target_host}/{target_port}"
	}
	ipTemplateRaw := strings.TrimSpace(e.options.TemplateIP)
	if ipTemplateRaw == "" {
		ipTemplateRaw = "https://masque.local/masque/ip"
	}
	tcpTemplateRaw := strings.TrimSpace(e.options.TemplateTCP)
	if tcpTemplateRaw == "" {
		tcpTemplateRaw = "https://masque.local/masque/tcp/{target_host}/{target_port}"
	}
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
	udpPath := pathFromTemplate(udpTemplateRaw)
	ipPath := pathFromTemplate(ipTemplateRaw)
	tcpPath := pathFromTemplate(tcpTemplateRaw)
	udpProxy := &qmasque.Proxy{}
	e.udpProxy = udpProxy
	ipProxy := &connectip.Proxy{}
	mux := http.NewServeMux()
	mux.HandleFunc(udpPath, func(w http.ResponseWriter, r *http.Request) {
		if !e.authorizeRequest(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		req, err := qmasque.ParseRequest(r, udpTemplate)
		if err != nil {
			var perr *qmasque.RequestParseError
			if errors.As(err, &perr) {
				w.WriteHeader(perr.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := udpProxy.Proxy(w, req); err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
	})
	mux.HandleFunc(ipPath, func(w http.ResponseWriter, r *http.Request) {
		e.logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip request method=%s remote=%s uri=%s", r.Method, r.RemoteAddr, r.URL.String()))
		if !e.authorizeRequest(r) {
			e.logger.DebugContext(r.Context(), "masque connect-ip auth denied status=401")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		req, err := connectip.ParseRequest(r, ipTemplate)
		if err != nil {
			status := connectIPRequestErrorHTTPStatus(err)
			e.logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip parse denied status=%d error_class=%s err=%v", status, connectIPRequestErrorClass(status), err))
			w.WriteHeader(status)
			return
		}
		conn, err := ipProxy.Proxy(w, req)
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
		routePacketConnectionExBypassTunnelWrapper(e.router, r.Context(), packetConn, metadata, func(err error) {
			if err != nil && !errors.Is(err, context.Canceled) {
				e.logger.DebugContext(r.Context(), fmt.Sprintf("masque connect-ip route closed err=%v", err))
			}
			_ = packetConn.Close()
		})
	})
	mux.HandleFunc(tcpPath, func(w http.ResponseWriter, r *http.Request) {
		e.handleTCPConnectRequest(w, r, tcpTemplate)
	})
	listenHost := strings.TrimSpace(e.options.Listen)
	if listenHost == "" {
		listenHost = "0.0.0.0"
	}
	addr := net.JoinHostPort(listenHost, strconv.Itoa(int(e.options.ListenPort)))
	e.server = &http3.Server{
		Addr:            addr,
		Handler:         mux,
		TLSConfig:       http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{tlsCert}}),
		EnableDatagrams: true,
		QUICConfig: &quic.Config{
			EnableDatagrams: true,
			MaxIdleTimeout:  24 * time.Hour,
			KeepAlivePeriod: 15 * time.Second,
		},
	}
	packetConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return E.Cause(err, "listen udp for masque server")
	}
	e.packetConn = packetConn
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

func routePacketConnectionExBypassTunnelWrapper(router adapter.Router, ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
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
	if e.server != nil {
		_ = e.server.Close()
		e.server = nil
	}
	if e.packetConn != nil {
		err := e.packetConn.Close()
		e.packetConn = nil
		return err
	}
	return nil
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
	return nil, E.New("invalid destination")
}

func (e *ServerEndpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := e.lastStartError(); err != nil {
		return nil, E.Cause(err, "masque server startup failed")
	}
	return net.ListenPacket("udp", "")
}

func (e *ServerEndpoint) authorizeRequest(r *http.Request) bool {
	required := strings.TrimSpace(e.options.ServerToken)
	if required == "" {
		return true
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(auth[7:])), []byte(required)) == 1
	}
	proxyAuth := strings.TrimSpace(r.Header.Get("Proxy-Authorization"))
	if strings.HasPrefix(strings.ToLower(proxyAuth), "bearer ") {
		return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(proxyAuth[7:])), []byte(required)) == 1
	}
	return false
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

func (e *ServerEndpoint) handleTCPConnectRequest(w http.ResponseWriter, r *http.Request, tcpTemplate *uritemplate.Template) {
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
	targetHost, targetPort, parseErr := parseTCPTargetFromRequest(r, tcpTemplate)
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
		_, err := io.Copy(targetConn, reqBody)
		if cw, ok := targetConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		uploadErrCh <- err
	}()
	go func() {
		out := io.Writer(responseWriter)
		if flusher, ok := responseWriter.(http.Flusher); ok {
			out = &flushWriter{w: responseWriter, f: flusher}
		}
		_, err := io.Copy(out, targetConn)
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
	f http.Flusher
}

func (w *flushWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if n > 0 {
		w.f.Flush()
	}
	return n, err
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
			return M.Socksaddr{}, err
		}
		buffer.Truncate(n)
		destination, payloadStart, payloadEnd, parseErr := parseIPDestinationAndPayload(buffer.Bytes())
		if parseErr != nil {
			connectIPServerParseDropTotal.Add(1)
			buffer.Reset()
			continue
		}
		if payloadStart > 0 || payloadEnd < n {
			payloadLen := payloadEnd - payloadStart
			copy(buffer.Bytes()[:payloadLen], buffer.Bytes()[payloadStart:payloadEnd])
			buffer.Truncate(payloadLen)
		}
		return destination, nil
	}
}

func (c *connectIPNetPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return c.writeOutgoingWithICMPRelay(buffer.Bytes())
}

// Relay PTB/control feedback returned by connect-ip-go (ICMP payload as a full IP packet).
const connectIPMaxICMPRelay = 8

func (c *connectIPNetPacketConn) writeOutgoingWithICMPRelay(packet []byte) error {
	payload := packet
	for i := 0; i < connectIPMaxICMPRelay; i++ {
		icmp, err := c.conn.WritePacket(payload)
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
			return 0, nil, err
		}
		destination, payloadStart, payloadEnd, parseErr := parseIPDestinationAndPayload(p[:n])
		if parseErr != nil {
			connectIPServerParseDropTotal.Add(1)
			continue
		}
		if payloadStart > 0 || payloadEnd < n {
			payloadLen := payloadEnd - payloadStart
			copy(p[:payloadLen], p[payloadStart:payloadEnd])
			n = payloadLen
		}
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

type connDeadlines struct {
	mu    sync.RWMutex
	read  time.Time
	write time.Time
}

func (d *connDeadlines) setDeadline(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.read = t
	d.write = t
}

func (d *connDeadlines) setReadDeadline(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.read = t
}

func (d *connDeadlines) setWriteDeadline(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.write = t
}

func (d *connDeadlines) readTimeout() (time.Duration, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.read.IsZero() {
		return 0, false
	}
	timeout := time.Until(d.read)
	if timeout <= 0 {
		return 0, true
	}
	return timeout, true
}

func (d *connDeadlines) readTimeoutExceeded() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return !d.read.IsZero() && time.Now().After(d.read)
}

func (d *connDeadlines) writeTimeoutExceeded() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return !d.write.IsZero() && time.Now().After(d.write)
}

func parseTCPTargetFromRequest(r *http.Request, template *uritemplate.Template) (string, string, error) {
	if r.Method != http.MethodConnect {
		return "", "", E.New("expected CONNECT request")
	}
	templateURL, err := url.Parse(template.Raw())
	if err != nil {
		return "", "", E.Cause(err, "parse tcp template")
	}
	if templateURL.Host != "" && !strings.EqualFold(strings.TrimSpace(r.Host), strings.TrimSpace(templateURL.Host)) {
		return "", "", E.New("CONNECT authority does not match TCP template host")
	}
	candidates := []string{
		strings.TrimSpace(r.URL.String()),
		strings.TrimSpace(r.URL.Path),
		strings.TrimSpace(r.RequestURI),
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

func parseIPDestination(packet []byte) (M.Socksaddr, error) {
	destination, _, _, err := parseIPDestinationAndPayload(packet)
	return destination, err
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
		nextHeader := packet[6]
		if (nextHeader == 6 || nextHeader == 17) && len(packet) >= 44 {
			destination.Port = uint16(packet[42])<<8 | uint16(packet[43])
		}
		payloadStart, payloadEnd := 0, len(packet)
		if nextHeader == 17 && len(packet) >= 48 {
			payloadStart = 48
			payloadEnd = len(packet)
			udpLen := int(uint16(packet[44])<<8 | uint16(packet[45]))
			if udpLen >= 8 {
				payloadEnd = intMin(payloadEnd, 40+udpLen)
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

func intMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

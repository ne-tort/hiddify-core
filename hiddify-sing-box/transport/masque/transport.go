package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	qmasque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

const defaultUDPInitialPacketSize uint16 = 1350

type ClientSession interface {
	DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
	ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
	OpenIPSession(ctx context.Context) (IPPacketSession, error)
	Capabilities() CapabilitySet
	Close() error
}

type ClientFactory interface {
	NewSession(ctx context.Context, options ClientOptions) (ClientSession, error)
}

type CapabilitySet struct {
	ExtendedConnect bool
	Datagrams       bool
	CapsuleProtocol bool
	ConnectUDP      bool
	ConnectIP       bool
	ConnectTCP      bool
}

var (
	ErrTCPPathNotImplemented  = errors.New("tcp path is not implemented for selected MASQUE transport")
	ErrTCPOverConnectIP       = errors.New("tcp over connect-ip path is not implemented yet")
	ErrPolicyFallbackDenied   = errors.New("masque tcp fallback policy denied")
	ErrTCPConnectStreamFailed = errors.New("masque tcp connect-stream failed")
)

type ClientOptions struct {
	Tag              string
	Server           string
	ServerPort       uint16
	TransportMode    string
	TemplateUDP      string
	TemplateIP       string
	TemplateTCP      string
	FallbackPolicy   string
	TCPMode          string
	TCPTransport     string
	ServerToken      string
	TLSServerName    string
	Insecure         bool
	QUICExperimental QUICExperimentalOptions
	Hops             []HopOptions
	QUICDial         QUICDialFunc
}

type QUICExperimentalOptions struct {
	Enabled                    bool
	KeepAlivePeriod            time.Duration
	MaxIdleTimeout             time.Duration
	InitialStreamReceiveWindow uint64
	MaxStreamReceiveWindow     uint64
	InitialConnectionWindow    uint64
	MaxConnectionWindow        uint64
	MaxIncomingStreams         int64
	DisablePathMTUDiscovery    bool
}

type QUICDialFunc func(ctx context.Context, address string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error)

type HopOptions struct {
	Tag    string
	Via    string
	Server string
	Port   uint16
}

type IPPacketSession interface {
	ReadPacket(buffer []byte) (int, error)
	WritePacket(buffer []byte) error
	Close() error
}

type DirectClientFactory struct{}

func (f DirectClientFactory) NewSession(ctx context.Context, options ClientOptions) (ClientSession, error) {
	return &directSession{
		dialer:       net.Dialer{},
		capabilities: CapabilitySet{ConnectUDP: true, ConnectIP: false, ConnectTCP: true},
	}, nil
}

type directSession struct {
	dialer       net.Dialer
	capabilities CapabilitySet
}

func (s *directSession) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch strings.ToLower(network) {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, E.New("unsupported network in masque session: ", network)
	}
	if destination.IsFqdn() {
		return s.dialer.DialContext(ctx, network, net.JoinHostPort(destination.Fqdn, strconv.Itoa(int(destination.Port))))
	}
	if destination.Addr.IsValid() {
		return s.dialer.DialContext(ctx, network, net.JoinHostPort(destination.Addr.String(), strconv.Itoa(int(destination.Port))))
	}
	return nil, E.New("invalid destination")
}

func (s *directSession) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !s.capabilities.ConnectUDP {
		return nil, E.New("masque backend does not support CONNECT-UDP")
	}
	return net.ListenPacket("udp", "")
}

func (s *directSession) OpenIPSession(ctx context.Context) (IPPacketSession, error) {
	if !s.capabilities.ConnectIP {
		return nil, E.New("masque backend does not support CONNECT-IP")
	}
	return nil, E.New("CONNECT-IP is not available in direct backend")
}

func (s *directSession) Capabilities() CapabilitySet {
	return s.capabilities
}

func (s *directSession) Close() error { return nil }

type CoreClientFactory struct{}

func (f CoreClientFactory) NewSession(ctx context.Context, options ClientOptions) (ClientSession, error) {
	templateUDP, templateIP, templateTCP, err := buildTemplates(options)
	if err != nil {
		return nil, err
	}
	tcpTransport := normalizeTCPTransport(options.TCPTransport)
	tcpCapable := tcpTransport == "connect_stream" || tcpTransport == "connect_ip"
	return &coreSession{
		options:      options,
		templateUDP:  templateUDP,
		templateIP:   templateIP,
		templateTCP:  templateTCP,
		capabilities: CapabilitySet{ExtendedConnect: true, Datagrams: true, CapsuleProtocol: true, ConnectUDP: true, ConnectIP: true, ConnectTCP: tcpCapable},
		hopOrder:     resolveHopOrder(options.Hops),
		tcpFactory:   DefaultTCPNetstackFactory,
	}, nil
}

type coreSession struct {
	mu           sync.Mutex
	options      ClientOptions
	udpClient    *qmasque.Client
	ipConn       *connectip.Conn
	ipHTTPConn   *http3.ClientConn
	tcpHTTP      *http3.Transport
	templateUDP  *uritemplate.Template
	templateIP   *uritemplate.Template
	templateTCP  *uritemplate.Template
	capabilities CapabilitySet
	hopOrder     []HopOptions
	hopIndex     int
	tcpOverIP    *tcpOverIPDialer
	tcpFactory   TCPNetstackFactory
}

func (s *coreSession) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !isTCPNetwork(network) {
		return nil, E.New("unsupported network in masque session: ", network)
	}
	switch normalizeTCPTransport(s.options.TCPTransport) {
	case "connect_stream":
		return s.dialTCPStream(ctx, destination)
	case "connect_ip":
		return s.dialTCPOverIP(ctx, destination)
	default:
		return nil, ErrTCPPathNotImplemented
	}
}

func (s *coreSession) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.capabilities.ConnectUDP {
		return nil, E.New("masque backend does not support CONNECT-UDP")
	}
	if s.udpClient == nil {
		s.udpClient = s.newUDPClient()
	}
	target := net.JoinHostPort(s.resolveDestinationHost(destination), strconv.Itoa(int(destination.Port)))
	conn, _, err := s.udpClient.DialAddr(ctx, s.templateUDP, target)
	if err != nil {
		// first retry: same hop, force client re-dial
		_ = s.udpClient.Close()
		s.udpClient = s.newUDPClient()
		conn, _, err = s.udpClient.DialAddr(ctx, s.templateUDP, target)
		if err == nil {
			return conn, nil
		}
		for s.advanceHop() {
			if resetErr := s.resetHopTemplates(); resetErr != nil {
				return nil, resetErr
			}
			if s.udpClient == nil {
				s.udpClient = s.newUDPClient()
			}
			conn, _, err = s.udpClient.DialAddr(ctx, s.templateUDP, target)
			if err == nil {
				return conn, nil
			}
		}
		return nil, err
	}
	return conn, nil
}

func (s *coreSession) newUDPClient() *qmasque.Client {
	return &qmasque.Client{
		TLSClientConfig: &tls.Config{
			NextProtos:         []string{http3.NextProtoH3},
			InsecureSkipVerify: s.options.Insecure,
			ServerName:         resolveTLSServerName(s.options),
		},
		QUICConfig: applyQUICExperimentalOptions(&quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: defaultUDPInitialPacketSize,
		}, s.options.QUICExperimental),
		QUICDial: s.options.QUICDial,
	}
}

func (s *coreSession) OpenIPSession(ctx context.Context) (IPPacketSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.openIPSessionLocked(ctx)
}

func (s *coreSession) openIPSessionLocked(ctx context.Context) (IPPacketSession, error) {
	// caller must hold s.mu when calling directly.
	if !s.capabilities.ConnectIP {
		return nil, E.New("masque backend does not support CONNECT-IP")
	}
	if s.ipConn != nil {
		return &connectIPPacketSession{conn: s.ipConn}, nil
	}
	clientConn, err := s.openHTTP3ClientConn(ctx)
	if err != nil {
		return nil, err
	}
	conn, _, err := connectip.Dial(ctx, clientConn, s.templateIP)
	if err != nil {
		for s.advanceHop() {
			if resetErr := s.resetHopTemplates(); resetErr != nil {
				return nil, resetErr
			}
			clientConn, err = s.openHTTP3ClientConn(ctx)
			if err != nil {
				continue
			}
			conn, _, err = connectip.Dial(ctx, clientConn, s.templateIP)
			if err == nil {
				s.ipConn = conn
				return &connectIPPacketSession{conn: conn}, nil
			}
		}
		return nil, err
	}
	s.ipConn = conn
	return &connectIPPacketSession{conn: conn}, nil
}

func (s *coreSession) Capabilities() CapabilitySet {
	return s.capabilities
}

func (s *coreSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	if s.ipConn != nil {
		errs = append(errs, s.ipConn.Close())
	}
	if s.udpClient != nil {
		errs = append(errs, s.udpClient.Close())
	}
	if s.tcpHTTP != nil {
		s.tcpHTTP.Close()
	}
	if s.tcpOverIP != nil {
		errs = append(errs, s.tcpOverIP.Close())
		s.tcpOverIP = nil
	}
	return errors.Join(errs...)
}

func (s *coreSession) resolveDestinationHost(destination M.Socksaddr) string {
	if destination.IsFqdn() {
		return destination.Fqdn
	}
	if destination.Addr.IsValid() {
		return destination.Addr.String()
	}
	return "127.0.0.1"
}

func (s *coreSession) openHTTP3ClientConn(ctx context.Context) (*http3.ClientConn, error) {
	if s.ipHTTPConn != nil {
		return s.ipHTTPConn, nil
	}
	target := net.JoinHostPort(s.options.Server, strconv.Itoa(int(s.options.ServerPort)))
	tlsConf := &tls.Config{
		NextProtos:         []string{http3.NextProtoH3},
		InsecureSkipVerify: s.options.Insecure,
		ServerName:         resolveTLSServerName(s.options),
	}
	transport := &http3.Transport{
		EnableDatagrams: true,
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			if s.options.QUICDial != nil {
				return s.options.QUICDial(ctx, addr, tlsCfg, cfg)
			}
			return quic.DialAddr(ctx, addr, tlsCfg, cfg)
		},
	}
	conn, err := transport.Dial(ctx, target, tlsConf, applyQUICExperimentalOptions(&quic.Config{EnableDatagrams: true}, s.options.QUICExperimental))
	if err != nil {
		return nil, err
	}
	s.ipHTTPConn = transport.NewClientConn(conn)
	return s.ipHTTPConn, nil
}

func buildTemplates(options ClientOptions) (*uritemplate.Template, *uritemplate.Template, *uritemplate.Template, error) {
	if len(options.Hops) > 0 {
		server, port, err := resolveEntryHop(resolveHopOrder(options.Hops))
		if err != nil {
			return nil, nil, nil, err
		}
		if strings.TrimSpace(server) != "" && port != 0 {
			options.Server = server
			options.ServerPort = port
		}
	}
	if options.ServerPort == 0 {
		options.ServerPort = 443
	}
	udpRaw := strings.TrimSpace(options.TemplateUDP)
	if udpRaw == "" {
		udpRaw = fmt.Sprintf("https://%s:%d/masque/udp/{target_host}/{target_port}", options.Server, options.ServerPort)
	}
	ipRaw := strings.TrimSpace(options.TemplateIP)
	if ipRaw == "" {
		ipRaw = fmt.Sprintf("https://%s:%d/masque/ip", options.Server, options.ServerPort)
	}
	tcpRaw := strings.TrimSpace(options.TemplateTCP)
	if tcpRaw == "" {
		tcpRaw = fmt.Sprintf("https://%s:%d/masque/tcp/{target_host}/{target_port}", options.Server, options.ServerPort)
	}
	udpTemplate, err := uritemplate.New(udpRaw)
	if err != nil {
		return nil, nil, nil, E.Cause(err, "invalid UDP MASQUE template")
	}
	ipTemplate, err := uritemplate.New(ipRaw)
	if err != nil {
		return nil, nil, nil, E.Cause(err, "invalid IP MASQUE template")
	}
	if _, err := url.Parse(udpRaw); err != nil {
		return nil, nil, nil, E.Cause(err, "invalid UDP MASQUE URL")
	}
	if _, err := url.Parse(ipRaw); err != nil {
		return nil, nil, nil, E.Cause(err, "invalid IP MASQUE URL")
	}
	tcpTemplate, err := uritemplate.New(tcpRaw)
	if err != nil {
		return nil, nil, nil, E.Cause(err, "invalid TCP MASQUE template")
	}
	if _, err := url.Parse(tcpRaw); err != nil {
		return nil, nil, nil, E.Cause(err, "invalid TCP MASQUE URL")
	}
	return udpTemplate, ipTemplate, tcpTemplate, nil
}

func resolveEntryHop(hops []HopOptions) (string, uint16, error) {
	entries := make([]HopOptions, 0, len(hops))
	for _, hop := range hops {
		if strings.TrimSpace(hop.Via) == "" {
			entries = append(entries, hop)
		}
	}
	if len(entries) == 0 {
		return "", 0, E.New("masque chain has no entry hop")
	}
	if len(entries) > 1 {
		return "", 0, E.New("masque chain has multiple entry hops; unsupported runtime topology")
	}
	entry := entries[0]
	return entry.Server, entry.Port, nil
}

func resolveHopOrder(hops []HopOptions) []HopOptions {
	if len(hops) == 0 {
		return nil
	}
	nextByVia := make(map[string]HopOptions, len(hops))
	var root HopOptions
	for _, hop := range hops {
		if strings.TrimSpace(hop.Via) == "" {
			root = hop
		} else {
			nextByVia[hop.Via] = hop
		}
	}
	if strings.TrimSpace(root.Tag) == "" {
		return hops
	}
	ordered := []HopOptions{root}
	for len(ordered) < len(hops) {
		next, ok := nextByVia[ordered[len(ordered)-1].Tag]
		if !ok {
			break
		}
		ordered = append(ordered, next)
	}
	if len(ordered) != len(hops) {
		return hops
	}
	return ordered
}

func (s *coreSession) advanceHop() bool {
	if len(s.hopOrder) == 0 || s.hopIndex+1 >= len(s.hopOrder) {
		return false
	}
	s.hopIndex++
	return true
}

func (s *coreSession) resetHopTemplates() error {
	// caller must hold s.mu
	if len(s.hopOrder) == 0 {
		return nil
	}
	hop := s.hopOrder[s.hopIndex]
	s.options.Server = hop.Server
	s.options.ServerPort = hop.Port
	udpTemplate, ipTemplate, tcpTemplate, err := buildTemplates(s.options)
	if err != nil {
		return err
	}
	s.templateUDP = udpTemplate
	s.templateIP = ipTemplate
	s.templateTCP = tcpTemplate
	if s.udpClient != nil {
		_ = s.udpClient.Close()
		s.udpClient = nil
	}
	s.ipConn = nil
	s.ipHTTPConn = nil
	if s.tcpOverIP != nil {
		_ = s.tcpOverIP.Close()
		s.tcpOverIP = nil
	}
	return nil
}

func (s *coreSession) dialTCPOverIP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	targetHost := s.resolveDestinationHost(destination)
	targetPort := destination.Port
	tcpTracef("masque tcp connect_ip dial start host=%s port=%d", targetHost, targetPort)
	s.mu.Lock()
	ipSession, err := s.openIPSessionLocked(ctx)
	if err != nil {
		s.mu.Unlock()
		wrapped := errors.Join(ErrTransportInit, err)
		tcpTracef("masque tcp connect_ip dial failed host=%s port=%d error_class=%s err=%v", targetHost, targetPort, ClassifyError(wrapped), wrapped)
		return nil, wrapped
	}
	if s.tcpOverIP == nil {
		s.tcpOverIP = newTCPOverIPDialer(s.tcpFactory, ipSession)
	}
	dialer := s.tcpOverIP
	s.mu.Unlock()
	conn, err := dialer.DialContext(ctx, destination)
	if err != nil {
		tcpTracef("masque tcp connect_ip dial failed host=%s port=%d error_class=%s err=%v", targetHost, targetPort, ClassifyError(err), err)
		return nil, err
	}
	tcpTracef("masque tcp connect_ip dial success host=%s port=%d status=200", targetHost, targetPort)
	return conn, nil
}

func resolveTLSServerName(options ClientOptions) string {
	if strings.TrimSpace(options.TLSServerName) != "" {
		return options.TLSServerName
	}
	return options.Server
}

func normalizeTCPTransport(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "connect_stream":
		return "connect_stream"
	case "connect_ip":
		return "connect_ip"
	default:
		return "auto"
	}
}

func (s *coreSession) dialTCPStream(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	s.mu.Lock()
	if s.templateTCP == nil {
		raw := strings.TrimSpace(s.options.TemplateTCP)
		if raw == "" {
			raw = fmt.Sprintf("https://%s:%d/masque/tcp/{target_host}/{target_port}", s.options.Server, s.options.ServerPort)
		}
		t, err := uritemplate.New(raw)
		if err != nil {
			s.mu.Unlock()
			return nil, E.Cause(err, "invalid TCP MASQUE template")
		}
		s.templateTCP = t
	}
	templateTCP := s.templateTCP
	options := s.options
	if s.tcpHTTP == nil {
		s.tcpHTTP = &http3.Transport{
			EnableDatagrams: true,
			TLSClientConfig: &tls.Config{
				NextProtos:         []string{http3.NextProtoH3},
				InsecureSkipVerify: options.Insecure,
				ServerName:         resolveTLSServerName(options),
			},
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				cfg = applyQUICExperimentalOptions(cfg, options.QUICExperimental)
				if options.QUICDial != nil {
					return options.QUICDial(ctx, addr, tlsCfg, cfg)
				}
				return quic.DialAddr(ctx, addr, tlsCfg, cfg)
			},
		}
	}
	tcpHTTP := s.tcpHTTP
	s.mu.Unlock()

	targetHost := s.resolveDestinationHost(destination)
	targetPort := destination.Port
	expanded, err := templateTCP.Expand(uritemplate.Values{
		"target_host": uritemplate.String(targetHost),
		"target_port": uritemplate.String(strconv.Itoa(int(destination.Port))),
	})
	if err != nil {
		return nil, E.Cause(err, "expand TCP MASQUE template")
	}
	tcpURL, err := url.Parse(expanded)
	if err != nil {
		return nil, E.Cause(err, "parse TCP MASQUE URL")
	}
	serverHost := tcpURL.Host
	if serverHost == "" {
		serverHost = net.JoinHostPort(options.Server, strconv.Itoa(int(options.ServerPort)))
	}
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		tcpTracef("masque tcp connect_stream request host=%s port=%d attempt=%d", targetHost, targetPort, attempt+1)
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodConnect, tcpURL.String(), nil)
		if reqErr != nil {
			return nil, E.Cause(reqErr, "build TCP MASQUE request")
		}
		req.Host = serverHost
		req.Proto = "HTTP/3"
		req.ProtoMajor = 3
		req.ProtoMinor = 0
		req.Header = make(http.Header)
		if token := strings.TrimSpace(options.ServerToken); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		pr, pw := io.Pipe()
		req.Body = pr
		req.ContentLength = -1
		resp, roundTripErr := tcpHTTP.RoundTrip(req)
		if roundTripErr != nil {
			_ = pr.Close()
			_ = pw.Close()
			if attempt+1 < maxAttempts && isRetryableTCPStreamError(roundTripErr) && ctx.Err() == nil {
				tcpTracef("masque tcp connect_stream retry host=%s port=%d attempt=%d error_class=%s err=%v", targetHost, targetPort, attempt+1, ClassifyError(ErrTCPConnectStreamFailed), roundTripErr)
				s.resetTCPHTTPTransport()
				s.mu.Lock()
				tcpHTTP = s.tcpHTTP
				s.mu.Unlock()
				if backoffErr := waitContextBackoff(ctx, time.Duration(attempt+1)*50*time.Millisecond); backoffErr != nil {
					return nil, backoffErr
				}
				continue
			}
			tcpTracef("masque tcp connect_stream failed host=%s port=%d status=roundtrip_error error_class=%s err=%v", targetHost, targetPort, ClassifyError(ErrTCPConnectStreamFailed), roundTripErr)
			return nil, fmt.Errorf("%w: %v", ErrTCPConnectStreamFailed, roundTripErr)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = pr.Close()
			_ = pw.Close()
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				tcpTracef("masque tcp connect_stream denied host=%s port=%d status=%d error_class=%s", targetHost, targetPort, resp.StatusCode, ClassifyError(ErrAuthFailed))
				return nil, errors.Join(ErrAuthFailed, fmt.Errorf("status=%d url=%s", resp.StatusCode, tcpURL.String()))
			}
			tcpTracef("masque tcp connect_stream failed host=%s port=%d status=%d error_class=%s", targetHost, targetPort, resp.StatusCode, ClassifyError(ErrTCPConnectStreamFailed))
			return nil, fmt.Errorf("%w: status=%d url=%s", ErrTCPConnectStreamFailed, resp.StatusCode, tcpURL.String())
		}
		tcpTracef("masque tcp connect_stream success host=%s port=%d status=%d", targetHost, targetPort, resp.StatusCode)
		remoteAddr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(targetHost, strconv.Itoa(int(destination.Port))))
		return &streamConn{
			reader: resp.Body,
			writer: pw,
			local:  &net.TCPAddr{},
			remote: remoteAddr,
		}, nil
	}
	return nil, fmt.Errorf("%w: exhausted retries", ErrTCPConnectStreamFailed)
}

func tcpTracef(format string, args ...any) {
	if strings.TrimSpace(os.Getenv("MASQUE_TRACE_TCP")) != "1" {
		return
	}
	log.Printf(format, args...)
}

func (s *coreSession) resetTCPHTTPTransport() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tcpHTTP != nil {
		s.tcpHTTP.Close()
	}
	s.tcpHTTP = &http3.Transport{
		EnableDatagrams: true,
		TLSClientConfig: &tls.Config{
			NextProtos:         []string{http3.NextProtoH3},
			InsecureSkipVerify: s.options.Insecure,
			ServerName:         resolveTLSServerName(s.options),
		},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			cfg = applyQUICExperimentalOptions(cfg, s.options.QUICExperimental)
			if s.options.QUICDial != nil {
				return s.options.QUICDial(ctx, addr, tlsCfg, cfg)
			}
			return quic.DialAddr(ctx, addr, tlsCfg, cfg)
		},
	}
}

func isRetryableTCPStreamError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "timeout") ||
		strings.Contains(s, "no recent network activity") ||
		strings.Contains(s, "idle timeout") ||
		strings.Contains(s, "application error")
}

func waitContextBackoff(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timer.C:
		return nil
	}
}

func applyQUICExperimentalOptions(base *quic.Config, opts QUICExperimentalOptions) *quic.Config {
	if base == nil {
		base = &quic.Config{}
	}
	config := base.Clone()
	if !opts.Enabled {
		return config
	}
	if opts.KeepAlivePeriod > 0 {
		config.KeepAlivePeriod = opts.KeepAlivePeriod
	}
	if opts.MaxIdleTimeout > 0 {
		config.MaxIdleTimeout = opts.MaxIdleTimeout
	}
	if opts.InitialStreamReceiveWindow > 0 {
		config.InitialStreamReceiveWindow = opts.InitialStreamReceiveWindow
	}
	if opts.MaxStreamReceiveWindow > 0 {
		config.MaxStreamReceiveWindow = opts.MaxStreamReceiveWindow
	}
	if opts.InitialConnectionWindow > 0 {
		config.InitialConnectionReceiveWindow = opts.InitialConnectionWindow
	}
	if opts.MaxConnectionWindow > 0 {
		config.MaxConnectionReceiveWindow = opts.MaxConnectionWindow
	}
	if opts.MaxIncomingStreams > 0 {
		config.MaxIncomingStreams = opts.MaxIncomingStreams
	}
	config.DisablePathMTUDiscovery = opts.DisablePathMTUDiscovery
	return config
}

type streamConn struct {
	mu     sync.Mutex
	reader io.ReadCloser
	writer io.WriteCloser
	local  net.Addr
	remote net.Addr
}

func (c *streamConn) CloseRead() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reader.Close()
}

func (c *streamConn) CloseWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writer.Close()
}

func (c *streamConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) { return c.writer.Write(p) }
func (c *streamConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	err1 := c.writer.Close()
	err2 := c.reader.Close()
	return errors.Join(err1, err2)
}
func (c *streamConn) LocalAddr() net.Addr  { return c.local }
func (c *streamConn) RemoteAddr() net.Addr { return c.remote }
func (c *streamConn) SetDeadline(t time.Time) error {
	errRead := c.SetReadDeadline(t)
	errWrite := c.SetWriteDeadline(t)
	return errors.Join(errRead, errWrite)
}
func (c *streamConn) SetReadDeadline(t time.Time) error {
	if deadlineConn, ok := c.reader.(interface{ SetReadDeadline(time.Time) error }); ok {
		return deadlineConn.SetReadDeadline(t)
	}
	return ErrDeadlineUnsupported
}
func (c *streamConn) SetWriteDeadline(t time.Time) error {
	if deadlineConn, ok := c.writer.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return deadlineConn.SetWriteDeadline(t)
	}
	return ErrDeadlineUnsupported
}

type connectIPPacketSession struct {
	conn *connectip.Conn
}

func (s *connectIPPacketSession) ReadPacket(buffer []byte) (int, error) {
	return s.conn.ReadPacket(buffer)
}

func (s *connectIPPacketSession) WritePacket(buffer []byte) error {
	_, err := s.conn.WritePacket(buffer)
	return err
}

func (s *connectIPPacketSession) Close() error {
	return s.conn.Close()
}

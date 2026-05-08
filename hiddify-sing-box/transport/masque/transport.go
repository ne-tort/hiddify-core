package masque

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	qmasque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

const defaultUDPInitialPacketSize uint16 = 1350

// connectIPUDPWriteBufPool backs CONNECT-IP UDP bridge egress builds (IPv4+UDP+payload).
// Avoids a process-global mutex on connectIPUDPPacketConn for buffer reuse; WritePacket copies before return.
var connectIPUDPWriteBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 2048)
		return &b
	},
}

const defaultConnectIPDatagramCeilingMax = 1500
const connectIPUDPWriteHardCap = 1152

// connectIPUDPDirectReadMin is the minimum caller buffer size for CONNECT-IP UDP ReadFrom to
// read the full IPv4 datagram straight into p (drops the staging copy via conn.readBuffer).
const connectIPUDPDirectReadMin = 2048

// connectIPDatagramCeilingMax is the inclusive upper bound for ConnectIPDatagramCeiling (full IP datagram bytes).
// Default 1500 for typical QUIC interoperability; override with HIDDIFY_MASQUE_DATAGRAM_CEILING_MAX in [1280, 65535] for lab jumbo.
func connectIPDatagramCeilingMax() int {
	raw := strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_DATAGRAM_CEILING_MAX"))
	if raw == "" {
		return defaultConnectIPDatagramCeilingMax
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1280 || n > 65535 {
		return defaultConnectIPDatagramCeilingMax
	}
	return n
}

// masqueUDPDatagramSplitConn splits large application UDP payloads for CONNECT-UDP so each
// WriteTo matches QUIC HTTP datagram sizing expectations (tunnel-originated UDP).
type masqueUDPDatagramSplitConn struct {
	net.PacketConn
	maxPayload int
}

func (c *masqueUDPDatagramSplitConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) <= c.maxPayload {
		return c.PacketConn.WriteTo(p, addr)
	}
	sent := 0
	for sent < len(p) {
		end := sent + c.maxPayload
		if end > len(p) {
			end = len(p)
		}
		n, err := c.PacketConn.WriteTo(p[sent:end], addr)
		sent += n
		if err != nil {
			return sent, err
		}
		if n == 0 {
			return sent, fmt.Errorf("masque: zero-length WriteTo on CONNECT-UDP split")
		}
	}
	return len(p), nil
}

// masquePacketPlaneQUICConfig applies defaults for CONNECT-IP / CONNECT-UDP over HTTP/3.
// quic-go's default MaxIdleTimeout (30s) can close a session during long bulk datagram
// transfers when pacing and receiver-side drain stretch wall-clock beyond the idle window.
func masquePacketPlaneQUICConfig(base *quic.Config) *quic.Config {
	if base == nil {
		base = &quic.Config{}
	} else {
		base = base.Clone()
	}
	if base.MaxIdleTimeout == 0 {
		base.MaxIdleTimeout = 24 * time.Hour
	}
	if base.KeepAlivePeriod == 0 {
		base.KeepAlivePeriod = 15 * time.Second
	}
	return base
}

func newMasqueQUICConfig() *quic.Config {
	return masquePacketPlaneQUICConfig(&quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: defaultUDPInitialPacketSize,
	})
}

// MasqueHTTPServerQUICConfig returns QUIC settings aligned with the MASQUE packet-plane
// client (idle timeout, keepalive, InitialPacketSize, datagrams) for HTTP/3 server listeners.
// The server previously used only partial defaults, diverging from dial paths and weakening
// high-rate CONNECT-IP / CONNECT-UDP symmetry with the client stack.
func MasqueHTTPServerQUICConfig() *quic.Config {
	return newMasqueQUICConfig()
}

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
	ErrUnsupportedNetwork     = errors.New("masque session unsupported network")
	ErrPolicyFallbackDenied   = errors.New("masque tcp fallback policy denied")
	ErrTCPConnectStreamFailed = errors.New("masque tcp connect-stream failed")
)

func unsupportedNetworkError(network string) error {
	return errors.Join(ErrUnsupportedNetwork, E.New("unsupported network in masque session: ", network))
}

type connectIPObservabilityCounters struct {
	ptbRxTotal                   atomic.Uint64
	packetWriteFailTotal         atomic.Uint64
	packetReadExitTotal          atomic.Uint64
	packetTxTotal                atomic.Uint64
	packetRxTotal                atomic.Uint64
	bytesTxTotal                 atomic.Uint64
	bytesRxTotal                 atomic.Uint64
	netstackReadInjectTotal      atomic.Uint64
	netstackReadDropInvalidTotal atomic.Uint64
	netstackWriteDequeuedTotal   atomic.Uint64
	netstackWriteAttemptTotal    atomic.Uint64
	netstackWriteSuccessTotal    atomic.Uint64
	bypassListenPacketTotal      atomic.Uint64
	openSessionTotal             atomic.Uint64
	engineIngressTotal           atomic.Uint64
	engineClassifiedTotal        atomic.Uint64
	engineDropTotal              atomic.Uint64
	engineICMPFeedbackTotal      atomic.Uint64
	enginePMTUUpdateTotal        atomic.Uint64
	engineEffectiveUDPPayload    atomic.Uint64
	bridgeUDPTXAttemptTotal      atomic.Uint64
	bridgeBuildTotal             atomic.Uint64
	bridgeWriteEnterTotal        atomic.Uint64
	bridgeWriteChunkTotal        atomic.Uint64
	bridgeWriteOkTotal           atomic.Uint64
	bridgeWriteErrTotal          atomic.Uint64
	firstTxMarkerEmitted         atomic.Uint32
	firstRxMarkerEmitted         atomic.Uint32
	emitSeq                      atomic.Uint64
	sessionSeq                   atomic.Uint64
	lastActiveEmitUnixMilli      atomic.Int64
	mu                           sync.Mutex
	sessionResetByReason         map[string]uint64
	packetWriteFailByReason      map[string]uint64
	packetReadDropByReason       map[string]uint64
	engineDropByReason           map[string]uint64
	enginePMTUUpdateByReason     map[string]uint64
	bridgeWriteErrByReason       map[string]uint64
	currentSessionID             string
	currentScopeTarget           string
	currentScopeIPProto          uint8
	lastPTBObsEmitUnixMilli      atomic.Int64
}

var connectIPCounters = connectIPObservabilityCounters{
	sessionResetByReason:     make(map[string]uint64),
	packetWriteFailByReason:  make(map[string]uint64),
	packetReadDropByReason:   make(map[string]uint64),
	engineDropByReason:       make(map[string]uint64),
	enginePMTUUpdateByReason: make(map[string]uint64),
	bridgeWriteErrByReason:   make(map[string]uint64),
}

func policyDropICMPReasonSnapshot() map[string]uint64 {
	breakdown := connectip.PolicyDropICMPReasonBreakdown()
	// Keep a stable reason-key contract for runtime artifacts even when
	// a given reject path wasn't triggered in this run.
	for _, reason := range []string{"src_not_allowed", "dst_not_allowed", "proto_not_allowed"} {
		if _, ok := breakdown[reason]; !ok {
			breakdown[reason] = 0
		}
	}
	return breakdown
}

type ClientOptions struct {
	Tag                      string
	Server                   string
	ServerPort               uint16
	TransportMode            string
	TemplateUDP              string
	TemplateIP               string
	ConnectIPScopeTarget     string
	ConnectIPScopeIPProto    uint8
	TemplateTCP              string
	FallbackPolicy           string
	TCPMode                  string
	TCPTransport             string
	ServerToken              string
	TLSServerName            string
	Insecure                 bool
	QUICExperimental         QUICExperimentalOptions
	ConnectIPDatagramCeiling uint32
	Hops                     []HopOptions
	QUICDial                 QUICDialFunc
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
	WritePacket(buffer []byte) (icmp []byte, err error)
	Close() error
}

type DirectClientFactory struct{}

func (f DirectClientFactory) NewSession(ctx context.Context, options ClientOptions) (ClientSession, error) {
	tcpTransport := normalizeTCPTransport(options.TCPTransport)
	return &directSession{
		dialer:       net.Dialer{},
		tcpTransport: tcpTransport,
		capabilities: CapabilitySet{ConnectUDP: true, ConnectIP: false, ConnectTCP: tcpTransport == "connect_stream"},
	}, nil
}

type directSession struct {
	dialer       net.Dialer
	tcpTransport string
	capabilities CapabilitySet
}

func (s *directSession) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch strings.ToLower(network) {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, unsupportedNetworkError(network)
	}
	switch s.tcpTransport {
	case "connect_stream":
	case "connect_ip":
		return nil, errors.Join(ErrTCPOverConnectIP, errors.New("connect_ip is TUN packet-plane only"))
	default:
		return nil, ErrTCPPathNotImplemented
	}
	host, err := resolveDestinationHost(destination)
	if err != nil {
		return nil, err
	}
	return s.dialer.DialContext(ctx, network, net.JoinHostPort(host, strconv.Itoa(int(destination.Port))))
}

func (s *directSession) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !s.capabilities.ConnectUDP {
		return nil, E.New("masque backend does not support CONNECT-UDP")
	}
	return net.ListenPacket("udp", "")
}

func (s *directSession) OpenIPSession(ctx context.Context) (IPPacketSession, error) {
	if !s.capabilities.ConnectIP {
		return nil, errors.Join(ErrCapability, errors.New("masque backend does not support CONNECT-IP"))
	}
	return nil, errors.Join(ErrCapability, errors.New("CONNECT-IP is not available in direct backend"))
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
	tcpCapable := tcpTransport == "connect_stream"
	effectiveCeiling := int(options.ConnectIPDatagramCeiling)
	if effectiveCeiling <= 0 {
		effectiveCeiling = 1280
	}
	if effectiveCeiling < 1280 {
		effectiveCeiling = 1280
	}
	ceilingMax := connectIPDatagramCeilingMax()
	if effectiveCeiling > ceilingMax {
		effectiveCeiling = ceilingMax
	}
	initialPayload := effectiveCeiling - 28
	if initialPayload < 512 {
		initialPayload = 512
	}
	if initialPayload > connectIPUDPWriteHardCap {
		initialPayload = connectIPUDPWriteHardCap
	}
	masqueUDPWriteMax := effectiveCeiling - 120
	if masqueUDPWriteMax < 512 {
		masqueUDPWriteMax = 512
	}
	const masqueUDPWriteHardCap = 1152
	if masqueUDPWriteMax > masqueUDPWriteHardCap {
		masqueUDPWriteMax = masqueUDPWriteHardCap
	}
	return &coreSession{
		options:                  options,
		templateUDP:              templateUDP,
		templateIP:               templateIP,
		templateTCP:              templateTCP,
		capabilities:             CapabilitySet{ExtendedConnect: true, Datagrams: true, CapsuleProtocol: true, ConnectUDP: true, ConnectIP: true, ConnectTCP: tcpCapable},
		hopOrder:                 resolveHopOrder(options.Hops),
		connectIPDatagramCeiling: effectiveCeiling,
		masqueUDPWriteMax:        masqueUDPWriteMax,
		connectIPPMTUState:       newConnectIPPMTUState(initialPayload, 512, initialPayload),
	}, nil
}

func newConnectIPPMTUState(currentPayload, minPayload, maxPayload int) *connectIPPMTUState {
	s := &connectIPPMTUState{}
	s.currentPayload.Store(int64(currentPayload))
	s.minPayload.Store(int64(minPayload))
	s.maxPayload.Store(int64(maxPayload))
	return s
}

type coreSession struct {
	mu                       sync.Mutex
	options                  ClientOptions
	udpClient                *qmasque.Client
	udpDial                  func(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error)
	ipConn                   *connectip.Conn
	ipHTTPConn               *http3.ClientConn
	ipHTTP                   *http3.Transport
	tcpHTTP                  *http3.Transport
	templateUDP              *uritemplate.Template
	templateIP               *uritemplate.Template
	templateTCP              *uritemplate.Template
	capabilities             CapabilitySet
	hopOrder                 []HopOptions
	hopIndex                 int
	connectIPDatagramCeiling int
	masqueUDPWriteMax        int
	connectIPPMTUState       *connectIPPMTUState
	tcpRoundTripper          http.RoundTripper
}

type connectIPUDPPacketConn struct {
	session         IPPacketSession
	localV4         netip.Addr
	localBind       *net.UDPAddr
	pmtuState       *connectIPPMTUState
	deadlines       connDeadlines
	readMu          sync.Mutex
	readBuffer      []byte
	readScratchAddr net.UDPAddr
	closed          atomic.Bool
}

// connectIPPMTUState tracks the effective UDP payload ceiling for the
// CONNECT-IP UDP bridge. The hot path (currentPayloadCeiling on every
// WriteTo, successSinceDecrease bumped on every successful chunk) reads
// and increments via atomics; the mutex orders consistent transitions on
// PTB feedback and recovery (rare).
type connectIPPMTUState struct {
	mu                   sync.Mutex
	currentPayload       atomic.Int64
	minPayload           atomic.Int64
	maxPayload           atomic.Int64
	successSinceDecrease atomic.Int64
	lastMinus64UnixMilli atomic.Int64
}

// connDeadlines stores read/write deadlines as Unix-nanosecond atomics
// (0 = no deadline). The hot ReadFrom/WriteTo path performs a single
// atomic.Load to check, avoiding per-packet RLock/RUnlock on a previously
// shared sync.RWMutex.
type connDeadlines struct {
	read  atomic.Int64
	write atomic.Int64
}

// parseICMPPTBHopMTU extracts the next-hop IP MTU from a full ICMP feedback IP packet
// (IPv4 carrying ICMP type 3 code 4, or IPv6 carrying ICMPv6 type 2).
func parseICMPPTBHopMTU(icmpFullPacket []byte) (ipMTU int, isIPv6 bool, ok bool) {
	if len(icmpFullPacket) < 20 {
		return 0, false, false
	}
	switch icmpFullPacket[0] >> 4 {
	case 4:
		ihl := int(icmpFullPacket[0]&0x0f) * 4
		if ihl < 20 || len(icmpFullPacket) < ihl+8 {
			return 0, false, false
		}
		if icmpFullPacket[9] != 1 {
			return 0, false, false
		}
		icmpOff := ihl
		if icmpFullPacket[icmpOff] != 3 || icmpFullPacket[icmpOff+1] != 4 {
			return 0, false, false
		}
		mtu := int(binary.BigEndian.Uint16(icmpFullPacket[icmpOff+6 : icmpOff+8]))
		return mtu, false, mtu >= 576 && mtu <= 65535
	case 6:
		if len(icmpFullPacket) < 48 {
			return 0, false, false
		}
		if icmpFullPacket[6] != 58 {
			return 0, false, false
		}
		icmpOff := 40
		if len(icmpFullPacket) < icmpOff+8 {
			return 0, false, false
		}
		if icmpFullPacket[icmpOff] != 2 || icmpFullPacket[icmpOff+1] != 0 {
			return 0, false, false
		}
		mtu := int(binary.BigEndian.Uint32(icmpFullPacket[icmpOff+4 : icmpOff+8]))
		return mtu, true, mtu >= 1280 && mtu <= 65535
	default:
		return 0, false, false
	}
}

func (s *coreSession) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !isTCPNetwork(network) {
		return nil, unsupportedNetworkError(network)
	}
	switch normalizeTCPTransport(s.options.TCPTransport) {
	case "connect_stream":
		conn, err := s.dialTCPStream(ctx, destination)
		if err == nil {
			return conn, nil
		}
		if tcpMasqueDirectFallbackEnabled(s.options) && isTCPMasqueDirectFallbackEligible(err, ctx) {
			if host, hostErr := resolveDestinationHost(destination); hostErr == nil {
				tcpTracef("masque tcp masque_or_direct+fallback=direct_explicit: CONNECT-stream failed, trying direct tcp host=%s port=%d", host, destination.Port)
			} else {
				tcpTracef("masque tcp masque_or_direct+fallback=direct_explicit: CONNECT-stream failed, direct tcp host resolution failed err=%v", hostErr)
			}
			return s.dialDirectTCP(ctx, network, destination)
		}
		return nil, err
	case "connect_ip":
		return nil, errors.Join(ErrTCPOverConnectIP, errors.New("connect_ip is TUN packet-plane only"))
	default:
		return nil, ErrTCPPathNotImplemented
	}
}

func (s *coreSession) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	targetHost, err := resolveDestinationHost(destination)
	if err != nil {
		return nil, err
	}
	target := net.JoinHostPort(targetHost, strconv.Itoa(int(destination.Port)))

	s.mu.Lock()
	if strings.EqualFold(strings.TrimSpace(s.options.TransportMode), "connect_ip") {
		ipSession, err := s.openIPSessionLocked(ctx)
		s.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return newConnectIPUDPPacketConn(ctx, ipSession), nil
	}
	if !s.capabilities.ConnectUDP {
		s.mu.Unlock()
		return nil, E.New("masque backend does not support CONNECT-UDP")
	}
	if s.udpClient == nil {
		s.udpClient = s.newUDPClient()
	}
	udpClient := s.udpClient
	templateUDP := s.templateUDP
	s.mu.Unlock()

	conn, err := s.dialUDPAddr(ctx, udpClient, templateUDP, target)
	if err != nil {
		// first retry: same hop, force client re-dial
		s.mu.Lock()
		if s.udpClient == udpClient && s.udpClient != nil {
			_ = s.udpClient.Close()
			s.udpClient = s.newUDPClient()
		} else if s.udpClient == nil {
			s.udpClient = s.newUDPClient()
		}
		udpClient = s.udpClient
		templateUDP = s.templateUDP
		s.mu.Unlock()

		conn, err = s.dialUDPAddr(ctx, udpClient, templateUDP, target)
		if err == nil {
			return &masqueUDPDatagramSplitConn{PacketConn: conn, maxPayload: s.masqueUDPWriteMax}, nil
		}

		s.mu.Lock()
		for {
			if !s.advanceHop() {
				s.mu.Unlock()
				return nil, err
			}
			if resetErr := s.resetHopTemplates(); resetErr != nil {
				s.mu.Unlock()
				return nil, resetErr
			}
			if s.udpClient == nil {
				s.udpClient = s.newUDPClient()
			}
			udpClient = s.udpClient
			templateUDP = s.templateUDP
			s.mu.Unlock()
			conn, err = s.dialUDPAddr(ctx, udpClient, templateUDP, target)
			if err == nil {
				return &masqueUDPDatagramSplitConn{PacketConn: conn, maxPayload: s.masqueUDPWriteMax}, nil
			}
			s.mu.Lock()
		}
	}
	return &masqueUDPDatagramSplitConn{PacketConn: conn, maxPayload: s.masqueUDPWriteMax}, nil
}

func (s *coreSession) dialUDPAddr(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
	if s.udpDial != nil {
		return s.udpDial(ctx, client, template, target)
	}
	conn, _, err := client.DialAddr(ctx, template, target)
	return conn, err
}

func newConnectIPUDPPacketConn(ctx context.Context, session IPPacketSession) net.PacketConn {
	localV4 := netip.MustParseAddr("198.18.0.2")
	maxDatagram := 1200
	pmtuState := newConnectIPPMTUState(1172, 512, 1172)
	if connectIPSession, ok := session.(*connectIPPacketSession); ok && connectIPSession.conn != nil {
		if connectIPSession.datagramCeiling > 0 {
			maxDatagram = connectIPSession.datagramCeiling
		}
		if cap := connectIPDatagramCeilingMax(); maxDatagram > cap {
			maxDatagram = cap
		}
		if connectIPSession.pmtuState != nil {
			pmtuState = connectIPSession.pmtuState
		}
		prefixCtx, cancel := context.WithTimeout(ctx, time.Second)
		prefixes, err := connectIPSession.conn.LocalPrefixes(prefixCtx)
		cancel()
		if err == nil {
			for _, prefix := range prefixes {
				addr := prefixPreferredAddress(prefix)
				if addr.Is4() {
					localV4 = addr
					break
				}
			}
		}
	}
	maxUDPPayload := maxDatagram - 28
	if maxUDPPayload <= 0 {
		maxUDPPayload = 512
	}
	if maxUDPPayload > connectIPUDPWriteHardCap {
		maxUDPPayload = connectIPUDPWriteHardCap
	}
	pmtuState.mu.Lock()
	pmtuState.maxPayload.Store(int64(maxUDPPayload))
	cur := pmtuState.currentPayload.Load()
	if cur <= 0 || cur > int64(maxUDPPayload) {
		cur = int64(maxUDPPayload)
		pmtuState.currentPayload.Store(cur)
	}
	if minP := pmtuState.minPayload.Load(); minP <= 0 || minP > cur {
		pmtuState.minPayload.Store(512)
	}
	currentPayload := int(cur)
	pmtuState.mu.Unlock()
	setConnectIPEngineEffectiveUDPPayload(currentPayload, "session_init")
	l4 := localV4.As4()
	localIP := net.IPv4(l4[0], l4[1], l4[2], l4[3])
	return &connectIPUDPPacketConn{
		session:         session,
		localV4:         localV4,
		localBind:       &net.UDPAddr{IP: localIP, Port: 53000},
		pmtuState:       pmtuState,
		readScratchAddr: net.UDPAddr{IP: make(net.IP, 0, 16)},
	}
}

func (c *connectIPUDPPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	if c.deadlines.readTimeoutExceeded() {
		return 0, nil, os.ErrDeadlineExceeded
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		var raw []byte
		if len(p) >= connectIPUDPDirectReadMin {
			n, err = c.session.ReadPacket(p)
			raw = p[:n]
		} else {
			rb := c.readBuffer
			if rb == nil {
				rb = make([]byte, 64*1024)
				c.readBuffer = rb
			}
			n, err = c.session.ReadPacket(rb)
			raw = rb[:n]
		}
		if err != nil {
			return 0, nil, err
		}
		connectIPCounters.engineIngressTotal.Add(1)
		payloadOff, payloadLen, src, srcPort, parseErr := parseIPv4UDPPacketOffsets(raw)
		if parseErr != nil {
			incConnectIPEngineDropReason("read_parse")
			if c.deadlines.readTimeoutExceeded() {
				return 0, nil, os.ErrDeadlineExceeded
			}
			continue
		}
		connectIPCounters.engineClassifiedTotal.Add(1)
		src4 := src.As4()
		c.readScratchAddr.IP = append(c.readScratchAddr.IP[:0], src4[:]...)
		c.readScratchAddr.Port = int(srcPort)
		if len(p) >= connectIPUDPDirectReadMin {
			if payloadLen > len(p) {
				return 0, nil, fmt.Errorf("connect-ip udp bridge: UDP payload exceeds read buffer (%d > %d)", payloadLen, len(p))
			}
			if payloadOff != 0 {
				copy(p[:payloadLen], p[payloadOff:payloadOff+payloadLen])
			}
			return payloadLen, &c.readScratchAddr, nil
		}
		return copy(p, raw[payloadOff:payloadOff+payloadLen]), &c.readScratchAddr, nil
	}
}

func (c *connectIPUDPPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if c.deadlines.writeTimeoutExceeded() {
		return 0, os.ErrDeadlineExceeded
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil || udpAddr.Port <= 0 {
		return 0, errors.New("connect-ip udp bridge requires UDP destination")
	}
	ip4 := udpAddr.IP.To4()
	if ip4 == nil {
		return 0, errors.New("connect-ip udp bridge requires valid IPv4 destination")
	}
	src4 := c.localV4.As4()
	dst4 := [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}
	dstPort := uint16(udpAddr.Port)
	const srcPort uint16 = 53000
	headerTemplate := newIPv4UDPHeaderTemplate(src4, srcPort, dst4, dstPort)

	bufPtr := connectIPUDPWriteBufPool.Get().(*[]byte)
	defer func() {
		b := *bufPtr
		b = b[:0]
		*bufPtr = b
		connectIPUDPWriteBufPool.Put(bufPtr)
	}()
	writeBuf := *bufPtr

	connectIPCounters.bridgeWriteEnterTotal.Add(1)
	connectIPCounters.bridgeUDPTXAttemptTotal.Add(1)
	maxPayload := c.currentPayloadCeiling()
	for offset := 0; offset < len(p); {
		connectIPCounters.bridgeWriteChunkTotal.Add(1)
		end := offset + maxPayload
		if end > len(p) {
			end = len(p)
		}
		// MTU/oversize spikes can happen on high-rate bursts. Shrink payload and retry
		// locally before failing the whole WriteTo to reduce avoidable packet loss.
		const localMTURetryMax = 3
		localRetries := 0
		for {
			packet, buildErr := buildIPv4UDPPacketInplaceHeaderV4(writeBuf, headerTemplate, p[offset:end])
			if buildErr != nil {
				connectIPCounters.bridgeWriteErrTotal.Add(1)
				connectIPCounters.mu.Lock()
				connectIPCounters.bridgeWriteErrByReason["build_packet"]++
				connectIPCounters.mu.Unlock()
				return 0, buildErr
			}
			connectIPCounters.bridgeBuildTotal.Add(1)
			writeBuf = packet[:0]
			*bufPtr = writeBuf
			icmp, writeErr := c.session.WritePacket(packet)
			err = writeErr
			if err == nil {
				connectIPCounters.bridgeWriteOkTotal.Add(1)
				connectIPCounters.engineClassifiedTotal.Add(1)
				// Active snapshot cadence runs in connectIPPacketSession.WritePacket (below);
				// avoid duplicate maybeEmit per datagram (syscalls + atomic contention).
				if len(icmp) > 0 {
					connectIPCounters.engineICMPFeedbackTotal.Add(1)
					if ipMTU, isV6, ok := parseICMPPTBHopMTU(icmp); ok {
						maxPayload = c.applyPTBToUDPPayload(ipMTU, isV6)
					} else {
						maxPayload = c.decreasePayloadCeiling("ptb_feedback")
					}
				} else {
					maxPayload = c.maybeRecoverPayloadCeiling()
				}
				break
			}
			if classifyConnectIPErrorReason(err) == "mtu" && localRetries < localMTURetryMax {
				nextPayload := c.decreasePayloadCeiling("local_mtu_error")
				if nextPayload > 0 {
					nextEnd := offset + nextPayload
					if nextEnd > len(p) {
						nextEnd = len(p)
					}
					// Retry only when chunk size can shrink (otherwise would spin).
					if nextEnd > offset && nextEnd < end {
						end = nextEnd
						localRetries++
						continue
					}
				}
			}
			connectIPCounters.bridgeWriteErrTotal.Add(1)
			connectIPCounters.mu.Lock()
			connectIPCounters.bridgeWriteErrByReason["session_write_packet"]++
			connectIPCounters.mu.Unlock()
			return 0, err
		}
		offset = end
	}
	return len(p), nil
}

func (c *connectIPUDPPacketConn) Close() error {
	c.closed.Store(true)
	return nil
}

func (c *connectIPUDPPacketConn) LocalAddr() net.Addr {
	return c.localBind
}

func (c *connectIPUDPPacketConn) SetDeadline(t time.Time) error {
	c.deadlines.setDeadline(t)
	return nil
}

func (c *connectIPUDPPacketConn) SetReadDeadline(t time.Time) error {
	c.deadlines.setReadDeadline(t)
	return nil
}

func (c *connectIPUDPPacketConn) SetWriteDeadline(t time.Time) error {
	c.deadlines.setWriteDeadline(t)
	return nil
}

// currentPayloadCeiling returns the current effective UDP payload ceiling.
// Hot path: invoked once per WriteTo / ReadFrom; lock-free read.
// Lazy initialisation to 1172 (very rare; only if session_init never ran)
// is performed under the mutex.
func (c *connectIPUDPPacketConn) currentPayloadCeiling() int {
	if c.pmtuState == nil {
		return 1172
	}
	if v := c.pmtuState.currentPayload.Load(); v > 0 {
		return int(v)
	}
	c.pmtuState.mu.Lock()
	if v := c.pmtuState.currentPayload.Load(); v > 0 {
		c.pmtuState.mu.Unlock()
		return int(v)
	}
	c.pmtuState.currentPayload.Store(1172)
	c.pmtuState.mu.Unlock()
	return 1172
}

func (c *connectIPUDPPacketConn) applyPTBToUDPPayload(ipPathMTU int, isIPv6 bool) int {
	if c.pmtuState == nil {
		return 1172
	}
	overhead := 28
	if isIPv6 {
		overhead = 48
	}
	udpMax := ipPathMTU - overhead
	if udpMax < 512 {
		udpMax = 512
	}
	c.pmtuState.mu.Lock()
	cur := c.pmtuState.currentPayload.Load()
	if cur <= 0 {
		cur = 1172
		c.pmtuState.currentPayload.Store(cur)
	}
	if maxP := c.pmtuState.maxPayload.Load(); maxP > 0 && int64(udpMax) > maxP {
		udpMax = int(maxP)
	}
	if int64(udpMax) < cur {
		c.pmtuState.currentPayload.Store(int64(udpMax))
		c.pmtuState.successSinceDecrease.Store(0)
		cur = int64(udpMax)
	}
	c.pmtuState.mu.Unlock()
	current := int(cur)
	setConnectIPEngineEffectiveUDPPayload(current, "ptb_mtu_hint")
	return current
}

func (c *connectIPUDPPacketConn) decreasePayloadCeiling(reason string) int {
	if c.pmtuState == nil {
		return 1172
	}
	const pmtuMinus64DebounceMs = 80
	c.pmtuState.mu.Lock()
	cur := c.pmtuState.currentPayload.Load()
	if cur <= 0 {
		cur = 1172
		c.pmtuState.currentPayload.Store(cur)
	}
	if reason == "ptb_feedback" {
		now := time.Now().UnixMilli()
		if last := c.pmtuState.lastMinus64UnixMilli.Load(); last != 0 && now-last < pmtuMinus64DebounceMs {
			c.pmtuState.mu.Unlock()
			return int(cur)
		}
		c.pmtuState.lastMinus64UnixMilli.Store(now)
	}
	minP := c.pmtuState.minPayload.Load()
	next := cur - 64
	if next < minP {
		next = minP
	}
	if next < cur {
		c.pmtuState.currentPayload.Store(next)
		c.pmtuState.successSinceDecrease.Store(0)
		cur = next
	}
	c.pmtuState.mu.Unlock()
	current := int(cur)
	setConnectIPEngineEffectiveUDPPayload(current, reason)
	return current
}

// maybeRecoverPayloadCeiling is called per successful chunk write.
// Hot fast path: lock-free atomic increment + threshold check; the mutex is
// taken only when an actual upward transition is required (~once every
// `recoverySuccessWindow` packets per session).
func (c *connectIPUDPPacketConn) maybeRecoverPayloadCeiling() int {
	if c.pmtuState == nil {
		return 1172
	}
	const recoverySuccessWindow = 256
	cur := c.pmtuState.currentPayload.Load()
	maxP := c.pmtuState.maxPayload.Load()
	if cur <= 0 {
		// Lazy initialise on the slow path.
		c.pmtuState.mu.Lock()
		cur = c.pmtuState.currentPayload.Load()
		if cur <= 0 {
			cur = 1172
			c.pmtuState.currentPayload.Store(cur)
		}
		maxP = c.pmtuState.maxPayload.Load()
		c.pmtuState.mu.Unlock()
	}
	n := c.pmtuState.successSinceDecrease.Add(1)
	if maxP > 0 && cur >= maxP {
		return int(cur)
	}
	if n < recoverySuccessWindow {
		return int(cur)
	}
	c.pmtuState.mu.Lock()
	cur = c.pmtuState.currentPayload.Load()
	maxP = c.pmtuState.maxPayload.Load()
	if maxP > 0 && cur >= maxP {
		c.pmtuState.mu.Unlock()
		return int(cur)
	}
	if c.pmtuState.successSinceDecrease.Load() < recoverySuccessWindow {
		c.pmtuState.mu.Unlock()
		return int(cur)
	}
	next := cur + 16
	if maxP > 0 && next > maxP {
		next = maxP
	}
	c.pmtuState.currentPayload.Store(next)
	c.pmtuState.successSinceDecrease.Store(0)
	c.pmtuState.mu.Unlock()
	setConnectIPEngineEffectiveUDPPayload(int(next), "recovery_increase")
	return int(next)
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

func buildIPv4UDPPacket(src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16, payload []byte) ([]byte, error) {
	return buildIPv4UDPPacketInplace(nil, src, srcPort, dst, dstPort, payload)
}

func buildIPv4UDPPacketInplace(buffer []byte, src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16, payload []byte) ([]byte, error) {
	if !src.Is4() || !dst.Is4() {
		return nil, errors.New("ipv4 udp packet builder requires ipv4 addresses")
	}
	return buildIPv4UDPPacketInplaceV4(buffer, src.As4(), srcPort, dst.As4(), dstPort, payload)
}

func buildIPv4UDPPacketInplaceV4(buffer []byte, src4 [4]byte, srcPort uint16, dst4 [4]byte, dstPort uint16, payload []byte) ([]byte, error) {
	return buildIPv4UDPPacketInplaceHeaderV4(buffer, newIPv4UDPHeaderTemplate(src4, srcPort, dst4, dstPort), payload)
}

func newIPv4UDPHeaderTemplate(src4 [4]byte, srcPort uint16, dst4 [4]byte, dstPort uint16) [28]byte {
	var header [28]byte
	header[0] = 0x45
	header[1] = 0x00
	binary.BigEndian.PutUint16(header[4:6], 0)
	binary.BigEndian.PutUint16(header[6:8], 0)
	header[8] = 64
	header[9] = 17
	copy(header[12:16], src4[:])
	copy(header[16:20], dst4[:])
	binary.BigEndian.PutUint16(header[20:22], srcPort)
	binary.BigEndian.PutUint16(header[22:24], dstPort)
	return header
}

func buildIPv4UDPPacketInplaceHeaderV4(buffer []byte, headerTemplate [28]byte, payload []byte) ([]byte, error) {
	const ipv4HeaderLen = 20
	const udpHeaderLen = 8
	totalLen := ipv4HeaderLen + udpHeaderLen + len(payload)
	packet := buffer
	if cap(packet) < totalLen {
		packet = make([]byte, totalLen)
	} else {
		packet = packet[:totalLen]
	}
	copy(packet[:udpHeaderLen+ipv4HeaderLen], headerTemplate[:])
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	// headerTemplate keeps bytes [10:12] zero so calculateIPv4Checksum below
	// always reads zeros for the checksum field even on a reused buffer.
	binary.BigEndian.PutUint16(packet[10:12], ipv4HeaderChecksum(packet[:ipv4HeaderLen]))
	binary.BigEndian.PutUint16(packet[24:26], uint16(udpHeaderLen+len(payload)))
	binary.BigEndian.PutUint16(packet[26:28], 0)
	copy(packet[28:], payload)
	return packet, nil
}

func parseIPv4UDPPacketOffsets(packet []byte) (payloadOff int, payloadLen int, src netip.Addr, srcPort uint16, err error) {
	if len(packet) < 28 {
		return 0, 0, netip.Addr{}, 0, errors.New("connect-ip udp bridge packet too short")
	}
	version := packet[0] >> 4
	if version != 4 {
		return 0, 0, netip.Addr{}, 0, errors.New("connect-ip udp bridge expects ipv4 packet")
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+8 {
		return 0, 0, netip.Addr{}, 0, errors.New("connect-ip udp bridge invalid ipv4 header length")
	}
	if packet[9] != 17 {
		return 0, 0, netip.Addr{}, 0, errors.New("connect-ip udp bridge expects udp protocol")
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen <= 0 || totalLen > len(packet) {
		totalLen = len(packet)
	}
	udpStart := ihl
	srcAddr := netip.AddrFrom4([4]byte{
		packet[12], packet[13], packet[14], packet[15],
	})
	srcPort = binary.BigEndian.Uint16(packet[udpStart : udpStart+2])
	udpLen := int(binary.BigEndian.Uint16(packet[udpStart+4 : udpStart+6]))
	udpPayloadStart := udpStart + 8
	if udpLen < 8 || udpPayloadStart > totalLen {
		return 0, 0, netip.Addr{}, 0, errors.New("connect-ip udp bridge invalid udp length")
	}
	payloadEnd := udpStart + udpLen
	if payloadEnd > totalLen {
		payloadEnd = totalLen
	}
	if udpPayloadStart > payloadEnd {
		return udpPayloadStart, 0, srcAddr, srcPort, nil
	}
	return udpPayloadStart, payloadEnd - udpPayloadStart, srcAddr, srcPort, nil
}

func parseIPv4UDPPacket(packet []byte) (payload []byte, src netip.Addr, srcPort uint16, err error) {
	off, ln, addr, sport, err := parseIPv4UDPPacketOffsets(packet)
	if err != nil {
		return nil, netip.Addr{}, 0, err
	}
	return packet[off : off+ln], addr, sport, nil
}

func ipv4HeaderChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (s *coreSession) newUDPClient() *qmasque.Client {
	return &qmasque.Client{
		TLSClientConfig: &tls.Config{
			NextProtos:         []string{http3.NextProtoH3},
			InsecureSkipVerify: s.options.Insecure,
			ServerName:         resolveTLSServerName(s.options),
		},
		QUICConfig: applyQUICExperimentalOptions(newMasqueQUICConfig(), s.options.QUICExperimental),
		QUICDial:   s.options.QUICDial,
	}
}

func (s *coreSession) OpenIPSession(ctx context.Context) (IPPacketSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.openIPSessionLocked(ctx)
}

func (s *coreSession) openIPSessionLocked(ctx context.Context) (IPPacketSession, error) {
	// caller must hold s.mu when calling directly.
	emitConnectIPObservabilityEvent("open_ip_session_begin")
	connectIPCounters.mu.Lock()
	connectIPCounters.currentScopeTarget = strings.TrimSpace(s.options.ConnectIPScopeTarget)
	connectIPCounters.currentScopeIPProto = s.options.ConnectIPScopeIPProto
	connectIPCounters.mu.Unlock()
	if !s.capabilities.ConnectIP {
		incConnectIPWriteFailReason("open_not_supported")
		emitConnectIPObservabilityEvent("open_ip_session_fail")
		return nil, E.New("masque backend does not support CONNECT-IP")
	}
	if s.ipConn != nil {
		emitConnectIPObservabilityEvent("open_ip_session_success_reuse")
		return &connectIPPacketSession{
			conn:            s.ipConn,
			datagramCeiling: s.connectIPDatagramCeiling,
			pmtuState:       s.connectIPPMTUState,
		}, nil
	}
	clientConn, err := s.openHTTP3ClientConn(ctx)
	if err != nil {
		incConnectIPWriteFailReason("open_http3_client_conn")
		emitConnectIPObservabilityEvent("open_ip_session_fail")
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
				connectIPCounters.openSessionTotal.Add(1)
				setConnectIPSessionID()
				emitConnectIPObservabilityEvent("open_ip_session_success")
				return &connectIPPacketSession{
					conn:            conn,
					datagramCeiling: s.connectIPDatagramCeiling,
					pmtuState:       s.connectIPPMTUState,
				}, nil
			}
		}
		incConnectIPWriteFailReason(classifyConnectIPErrorReason(err))
		emitConnectIPObservabilityEvent("open_ip_session_fail")
		return nil, err
	}
	s.ipConn = conn
	connectIPCounters.openSessionTotal.Add(1)
	setConnectIPSessionID()
	emitConnectIPObservabilityEvent("open_ip_session_success")
	return &connectIPPacketSession{
		conn:            conn,
		datagramCeiling: s.connectIPDatagramCeiling,
		pmtuState:       s.connectIPPMTUState,
	}, nil
}

func (s *coreSession) Capabilities() CapabilitySet {
	return s.capabilities
}

func (s *coreSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	emitConnectIPObservabilityEvent("session_close_begin")
	if s.ipConn != nil {
		errs = append(errs, s.ipConn.Close())
		s.ipConn = nil
	}
	if s.ipHTTP != nil {
		s.ipHTTP.Close()
		s.ipHTTP = nil
		s.ipHTTPConn = nil
	}
	if s.udpClient != nil {
		errs = append(errs, s.udpClient.Close())
		s.udpClient = nil
	}
	if s.tcpHTTP != nil {
		s.tcpHTTP.Close()
		s.tcpHTTP = nil
	}
	emitConnectIPObservabilityEvent("session_close_end")
	return errors.Join(errs...)
}

func resolveDestinationHost(destination M.Socksaddr) (string, error) {
	if destination.IsFqdn() {
		return destination.Fqdn, nil
	}
	if destination.Addr.IsValid() {
		return destination.Addr.String(), nil
	}
	return "", errors.Join(ErrCapability, E.New("invalid destination"))
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
			cfg = masquePacketPlaneQUICConfig(cfg)
			cfg = applyQUICExperimentalOptions(cfg, s.options.QUICExperimental)
			if s.options.QUICDial != nil {
				return s.options.QUICDial(ctx, addr, tlsCfg, cfg)
			}
			return quic.DialAddr(ctx, addr, tlsCfg, cfg)
		},
	}
	conn, err := transport.Dial(ctx, target, tlsConf, applyQUICExperimentalOptions(newMasqueQUICConfig(), s.options.QUICExperimental))
	if err != nil {
		return nil, err
	}
	s.ipHTTP = transport
	s.ipHTTPConn = transport.NewClientConn(conn)
	return s.ipHTTPConn, nil
}

func buildTemplates(options ClientOptions) (*uritemplate.Template, *uritemplate.Template, *uritemplate.Template, error) {
	if len(options.Hops) > 0 {
		server, port, err := resolveEntryHop(resolveHopOrder(options.Hops))
		if err != nil {
			return nil, nil, nil, err
		}
		if strings.TrimSpace(server) != "" {
			options.Server = server
		}
		if port != 0 {
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
	ipRaw, err := applyConnectIPFlowScope(ipRaw, options.ConnectIPScopeTarget, options.ConnectIPScopeIPProto)
	if err != nil {
		return nil, nil, nil, err
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

func applyConnectIPFlowScope(ipTemplateRaw string, scopeTarget string, scopeIPProto uint8) (string, error) {
	template, err := uritemplate.New(ipTemplateRaw)
	if err != nil {
		return "", E.Cause(err, "invalid IP MASQUE template")
	}
	varNames := template.Varnames()
	if len(varNames) == 0 {
		if strings.TrimSpace(scopeTarget) != "" || scopeIPProto != 0 {
			return "", errors.Join(
				ErrCapability,
				E.New("connect_ip_scope_* requires template_ip with flow forwarding variables {target}/{ipproto}"),
			)
		}
		return ipTemplateRaw, nil
	}
	values := uritemplate.Values{}
	for _, variable := range varNames {
		switch variable {
		case "target":
			target := strings.TrimSpace(scopeTarget)
			if target == "" {
				target = "0.0.0.0/0"
			}
			if _, parseErr := netip.ParsePrefix(target); parseErr != nil {
				return "", errors.Join(ErrCapability, E.New("invalid connect_ip_scope_target"))
			}
			values["target"] = uritemplate.String(target)
		case "ipproto":
			values["ipproto"] = uritemplate.String(strconv.Itoa(int(scopeIPProto)))
		default:
			return "", errors.Join(ErrCapability, E.New("template_ip contains unsupported flow forwarding variable"))
		}
	}
	expanded, err := template.Expand(values)
	if err != nil {
		return "", E.Cause(err, "expand IP MASQUE flow forwarding template")
	}
	if strings.TrimSpace(expanded) == "" {
		return "", E.New("empty IP MASQUE URL after flow forwarding expansion")
	}
	return expanded, nil
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
	incConnectIPSessionReset("hop_advance")
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
	if s.ipConn != nil {
		_ = s.ipConn.Close()
		s.ipConn = nil
	}
	if s.ipHTTP != nil {
		s.ipHTTP.Close()
		s.ipHTTP = nil
	}
	s.ipHTTPConn = nil
	if s.tcpHTTP != nil {
		s.tcpHTTP.Close()
		s.tcpHTTP = nil
	}
	return nil
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

func tcpMasqueDirectFallbackEnabled(opt ClientOptions) bool {
	return strings.EqualFold(strings.TrimSpace(opt.TCPMode), option.MasqueTCPModeMasqueOrDirect) &&
		strings.EqualFold(strings.TrimSpace(opt.FallbackPolicy), option.MasqueFallbackPolicyDirectExplicit)
}

// isTCPMasqueDirectFallbackEligible limits direct TCP fallback to CONNECT-stream failures after an
// explicit MasqueTCPModeMasqueOrDirect + MasqueFallbackPolicyDirectExplicit profile (validated in endpoint).
func isTCPMasqueDirectFallbackEligible(err error, ctx context.Context) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, ErrAuthFailed) || errors.Is(err, ErrLifecycleClosed) || errors.Is(err, net.ErrClosed) {
		return false
	}
	return errors.Is(err, ErrTCPConnectStreamFailed)
}

func (s *coreSession) dialDirectTCP(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d := net.Dialer{}
	targetHost, err := resolveDestinationHost(destination)
	if err != nil {
		return nil, err
	}
	port := strconv.Itoa(int(destination.Port))
	if strings.TrimSpace(targetHost) == "" {
		return nil, E.New("invalid masque direct-tcp destination host")
	}
	addr := net.JoinHostPort(targetHost, port)
	return d.DialContext(ctx, network, addr)
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
				cfg = masquePacketPlaneQUICConfig(cfg)
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

	targetHost, err := resolveDestinationHost(destination)
	if err != nil {
		return nil, err
	}
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
	var lastRoundTripErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctxErr := context.Cause(ctx); ctxErr != nil {
			return nil, errors.Join(ErrTCPConnectStreamFailed, ctxErr)
		}
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
		roundTripper := s.getTCPRoundTripper(tcpHTTP)
		resp, roundTripErr := roundTripper.RoundTrip(req)
		if roundTripErr != nil {
			lastRoundTripErr = roundTripErr
			_ = pr.Close()
			_ = pw.Close()
			if errors.Is(roundTripErr, context.Canceled) || errors.Is(roundTripErr, context.DeadlineExceeded) {
				tcpTracef("masque tcp connect_stream cancelled host=%s port=%d attempt=%d error_class=%s err=%v", targetHost, targetPort, attempt+1, ClassifyError(ErrTCPConnectStreamFailed), roundTripErr)
				return nil, errors.Join(ErrTCPConnectStreamFailed, roundTripErr)
			}
			if attempt+1 < maxAttempts && isRetryableTCPStreamError(roundTripErr) && ctx.Err() == nil {
				tcpTracef("masque tcp connect_stream retry host=%s port=%d attempt=%d error_class=%s err=%v", targetHost, targetPort, attempt+1, ClassifyError(ErrTCPConnectStreamFailed), roundTripErr)
				s.resetTCPHTTPTransport()
				s.mu.Lock()
				tcpHTTP = s.tcpHTTP
				s.mu.Unlock()
				if backoffErr := waitContextBackoff(ctx, time.Duration(attempt+1)*50*time.Millisecond); backoffErr != nil {
					return nil, errors.Join(ErrTCPConnectStreamFailed, backoffErr)
				}
				continue
			}
			tcpTracef("masque tcp connect_stream failed host=%s port=%d status=roundtrip_error error_class=%s err=%v", targetHost, targetPort, ClassifyError(ErrTCPConnectStreamFailed), roundTripErr)
			return nil, errors.Join(ErrTCPConnectStreamFailed, roundTripErr)
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
			ctx:    ctx,
			local:  &net.TCPAddr{},
			remote: remoteAddr,
		}, nil
	}
	if lastRoundTripErr != nil {
		return nil, errors.Join(ErrTCPConnectStreamFailed, lastRoundTripErr)
	}
	return nil, ErrTCPConnectStreamFailed
}

func (s *coreSession) getTCPRoundTripper(defaultTransport *http3.Transport) http.RoundTripper {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tcpRoundTripper != nil {
		return s.tcpRoundTripper
	}
	return defaultTransport
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
			cfg = masquePacketPlaneQUICConfig(cfg)
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
	// TCP CONNECT-STREAM retry budget is only for transient round-trip / QUIC / H3 failures.
	// Use typed contracts instead of string matching to keep behavior stable across platforms.
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// Treat handshake timeout as transient (covers some paths that don't surface a net.Error).
	var hsTimeout *quic.HandshakeTimeoutError
	if errors.As(err, &hsTimeout) {
		return true
	}
	// Closed connections are not retryable for CONNECT-STREAM dial; they typically indicate
	// a deterministic lifecycle outcome on this hop (or explicit shutdown).
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	return false
}

// Kept for test-level compatibility while CONNECT-IP TCP dial path is disabled in runtime.
func isRetryableConnectIPError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) {
		return true
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return false
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
	ctx    context.Context
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

func (c *streamConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if err == nil {
		return n, nil
	}
	if c.ctx != nil {
		if ctxErr := context.Cause(c.ctx); ctxErr != nil {
			return n, errors.Join(ErrTCPConnectStreamFailed, ctxErr)
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return n, errors.Join(ErrTCPConnectStreamFailed, err)
	}
	return n, err
}
func (c *streamConn) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	if err == nil {
		return n, nil
	}
	if c.ctx != nil {
		if ctxErr := context.Cause(c.ctx); ctxErr != nil {
			return n, errors.Join(ErrTCPConnectStreamFailed, ctxErr)
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return n, errors.Join(ErrTCPConnectStreamFailed, err)
	}
	return n, err
}
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

func isTCPNetwork(network string) bool {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "tcp", "tcp4", "tcp6":
		return true
	default:
		return false
	}
}

type connectIPPacketSession struct {
	conn            *connectip.Conn
	datagramCeiling int
	pmtuState       *connectIPPMTUState
}

func (s *connectIPPacketSession) ReadPacket(buffer []byte) (int, error) {
	n, err := s.conn.ReadPacket(buffer)
	if err != nil {
		connectIPCounters.packetReadExitTotal.Add(1)
		incConnectIPReadDropReason(classifyConnectIPErrorReason(err))
		emitConnectIPObservabilityEvent("packet_read_exit")
		return n, err
	}
	if n > 0 {
		connectIPCounters.packetRxTotal.Add(1)
		connectIPCounters.bytesRxTotal.Add(uint64(n))
		if connectIPCounters.firstRxMarkerEmitted.CompareAndSwap(0, 1) {
			emitConnectIPObservabilityEvent("first_packet_rx")
		}
		maybeEmitConnectIPActiveSnapshot()
	}
	return n, err
}

func (s *connectIPPacketSession) WritePacket(buffer []byte) ([]byte, error) {
	if s.datagramCeiling > 0 && len(buffer) > s.datagramCeiling {
		connectIPCounters.packetWriteFailTotal.Add(1)
		incConnectIPWriteFailReason("ceiling_reject")
		emitConnectIPObservabilityEvent("packet_write_fail_ceiling")
		return nil, errors.Join(ErrTransportInit, errors.New("connect-ip packet exceeds configured datagram ceiling"))
	}
	icmp, err := s.conn.WritePacket(buffer)
	if err != nil {
		connectIPCounters.packetWriteFailTotal.Add(1)
		incConnectIPWriteFailReason(classifyConnectIPErrorReason(err))
		emitConnectIPObservabilityEvent("packet_write_fail")
		return icmp, err
	}
	connectIPCounters.packetTxTotal.Add(1)
	connectIPCounters.bytesTxTotal.Add(uint64(len(buffer)))
	if connectIPCounters.firstTxMarkerEmitted.CompareAndSwap(0, 1) {
		emitConnectIPObservabilityEvent("first_packet_tx")
	}
	maybeEmitConnectIPActiveSnapshot()
	if len(icmp) > 0 {
		connectIPCounters.ptbRxTotal.Add(1)
		maybeEmitConnectIPPTBObs("packet_ptb_rx")
	}
	return icmp, err
}

func (s *connectIPPacketSession) Close() error {
	// The core session owns CONNECT-IP lifecycle. Closing this wrapper must not
	// tear down the shared underlying conn used by runtime packet-plane.
	return nil
}

func incConnectIPSessionReset(reason string) {
	if strings.TrimSpace(reason) == "" {
		reason = "unknown"
	}
	connectIPCounters.mu.Lock()
	connectIPCounters.sessionResetByReason[reason]++
	connectIPCounters.mu.Unlock()
	emitConnectIPObservabilityEvent("session_reset_" + reason)
}

func classifyConnectIPErrorReason(err error) string {
	if err == nil {
		return "unknown"
	}
	if errors.Is(err, connectip.ErrFlowForwardingUnsupported) {
		return "capability_flow_forwarding_unsupported"
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return "closed"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return "timeout"
		}
		if netErr.Temporary() {
			return "temporary"
		}
	}
	// MTU / payload size constraints should be observable without relying on error strings.
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return "mtu"
	}
	if errors.Is(err, syscall.EMSGSIZE) {
		return "mtu"
	}
	return "other"
}

func incConnectIPWriteFailReason(reason string) {
	if strings.TrimSpace(reason) == "" {
		reason = "unknown"
	}
	connectIPCounters.mu.Lock()
	connectIPCounters.packetWriteFailByReason[reason]++
	connectIPCounters.mu.Unlock()
}

func incConnectIPReadDropReason(reason string) {
	if strings.TrimSpace(reason) == "" {
		reason = "unknown"
	}
	connectIPCounters.mu.Lock()
	connectIPCounters.packetReadDropByReason[reason]++
	connectIPCounters.mu.Unlock()
}

func incConnectIPEngineDropReason(reason string) {
	if strings.TrimSpace(reason) == "" {
		reason = "unknown"
	}
	connectIPCounters.engineDropTotal.Add(1)
	connectIPCounters.mu.Lock()
	connectIPCounters.engineDropByReason[reason]++
	connectIPCounters.mu.Unlock()
}

func setConnectIPEngineEffectiveUDPPayload(payload int, reason string) {
	if payload < 0 {
		payload = 0
	}
	connectIPCounters.engineEffectiveUDPPayload.Store(uint64(payload))
	if strings.TrimSpace(reason) == "" {
		reason = "unknown"
	}
	connectIPCounters.enginePMTUUpdateTotal.Add(1)
	connectIPCounters.mu.Lock()
	connectIPCounters.enginePMTUUpdateByReason[reason]++
	connectIPCounters.mu.Unlock()
}

func setConnectIPSessionID() {
	seq := connectIPCounters.sessionSeq.Add(1)
	id := fmt.Sprintf("connect-ip-session-%d-%d", time.Now().UnixNano(), seq)
	connectIPCounters.mu.Lock()
	connectIPCounters.currentSessionID = id
	connectIPCounters.mu.Unlock()
	connectIPCounters.lastActiveEmitUnixMilli.Store(0)
	connectIPCounters.firstTxMarkerEmitted.Store(0)
	connectIPCounters.firstRxMarkerEmitted.Store(0)
	connectIPCounters.lastPTBObsEmitUnixMilli.Store(0)
}

func maybeEmitConnectIPPTBObs(reason string) {
	now := time.Now().UnixMilli()
	last := connectIPCounters.lastPTBObsEmitUnixMilli.Load()
	if last != 0 && now-last < 1000 {
		return
	}
	if !connectIPCounters.lastPTBObsEmitUnixMilli.CompareAndSwap(last, now) {
		return
	}
	emitConnectIPObservabilityEvent(reason)
}

// Active OBS snapshots are capped at ~1 Hz; invoking time/cas logic on every
// CONNECT-IP datagram RX/TX was measurable overhead under high throughput.
var connectIPActiveObsSampleCounter atomic.Uint64

// connectIPActiveObsSampleMask=127 → time-based throttle roughly every 128 hot-path calls once last emit exists.
const connectIPActiveObsSampleMask = uint64(127)

func maybeEmitConnectIPActiveSnapshot() {
	n := connectIPActiveObsSampleCounter.Add(1)
	last := connectIPCounters.lastActiveEmitUnixMilli.Load()
	if last != 0 && (n&connectIPActiveObsSampleMask) != 0 {
		return
	}
	now := time.Now().UnixMilli()
	if last != 0 && now-last < 1000 {
		return
	}
	if !connectIPCounters.lastActiveEmitUnixMilli.CompareAndSwap(last, now) {
		return
	}
	emitConnectIPObservabilityEvent("periodic_active")
}

// ObserveConnectIPServerReadError mirrors connectIPPacketSession.ReadPacket accounting when
// connectip.Conn.ReadPacket fails on the server packet plane (protocol/masque connectIPNetPacketConn).
func ObserveConnectIPServerReadError(err error) {
	if err == nil {
		return
	}
	connectIPCounters.packetReadExitTotal.Add(1)
	incConnectIPReadDropReason(classifyConnectIPErrorReason(err))
	emitConnectIPObservabilityEvent("packet_read_exit")
}

// ObserveConnectIPServerReadSuccess records one accepted inbound IP datagram (raw ReadPacket length)
// after parse succeeds on the server CONNECT-IP path.
func ObserveConnectIPServerReadSuccess(rawLen int) {
	if rawLen <= 0 {
		return
	}
	connectIPCounters.packetRxTotal.Add(1)
	connectIPCounters.bytesRxTotal.Add(uint64(rawLen))
	if connectIPCounters.firstRxMarkerEmitted.CompareAndSwap(0, 1) {
		emitConnectIPObservabilityEvent("first_packet_rx")
	}
	maybeEmitConnectIPActiveSnapshot()
}

// ObserveConnectIPServerWriteIteration mirrors one connectip.Conn.WritePacket hop from the server
// ICMP-relay loop (including PTB follow-up writes).
func ObserveConnectIPServerWriteIteration(payloadLen int, icmpLen int, err error) {
	if err != nil {
		connectIPCounters.packetWriteFailTotal.Add(1)
		incConnectIPWriteFailReason(classifyConnectIPErrorReason(err))
		emitConnectIPObservabilityEvent("packet_write_fail")
		return
	}
	if payloadLen <= 0 {
		return
	}
	connectIPCounters.packetTxTotal.Add(1)
	connectIPCounters.bytesTxTotal.Add(uint64(payloadLen))
	if connectIPCounters.firstTxMarkerEmitted.CompareAndSwap(0, 1) {
		emitConnectIPObservabilityEvent("first_packet_tx")
	}
	maybeEmitConnectIPActiveSnapshot()
	if icmpLen > 0 {
		connectIPCounters.ptbRxTotal.Add(1)
		maybeEmitConnectIPPTBObs("packet_ptb_rx")
	}
}

// connectIPServerParseDropSupplier is set from protocol/masque init (server CONNECT-IP parse drops).
var connectIPServerParseDropSupplier func() uint64

// RegisterConnectIPServerParseDropSupplier merges server-side parse-drop totals into CONNECT_IP_OBS snapshots.
func RegisterConnectIPServerParseDropSupplier(fn func() uint64) {
	connectIPServerParseDropSupplier = fn
}

func ConnectIPObservabilitySnapshot() map[string]any {
	connectIPCounters.mu.Lock()
	reasons := make(map[string]uint64, len(connectIPCounters.sessionResetByReason))
	for k, v := range connectIPCounters.sessionResetByReason {
		reasons[k] = v
	}
	writeReasons := make(map[string]uint64, len(connectIPCounters.packetWriteFailByReason))
	for k, v := range connectIPCounters.packetWriteFailByReason {
		writeReasons[k] = v
	}
	readReasons := make(map[string]uint64, len(connectIPCounters.packetReadDropByReason))
	for k, v := range connectIPCounters.packetReadDropByReason {
		readReasons[k] = v
	}
	engineDropReasons := make(map[string]uint64, len(connectIPCounters.engineDropByReason))
	for k, v := range connectIPCounters.engineDropByReason {
		engineDropReasons[k] = v
	}
	pmtuUpdateReasons := make(map[string]uint64, len(connectIPCounters.enginePMTUUpdateByReason))
	for k, v := range connectIPCounters.enginePMTUUpdateByReason {
		pmtuUpdateReasons[k] = v
	}
	bridgeWriteErrReasons := make(map[string]uint64, len(connectIPCounters.bridgeWriteErrByReason))
	for k, v := range connectIPCounters.bridgeWriteErrByReason {
		bridgeWriteErrReasons[k] = v
	}
	sessionID := connectIPCounters.currentSessionID
	scopeTarget := connectIPCounters.currentScopeTarget
	scopeIPProto := connectIPCounters.currentScopeIPProto
	connectIPCounters.mu.Unlock()
	out := map[string]any{
		"connect_ip_obs_contract_version":             "v1",
		"connect_ip_session_id":                       sessionID,
		"connect_ip_scope_target":                     scopeTarget,
		"connect_ip_scope_ipproto":                    scopeIPProto,
		"connect_ip_emit_seq":                         connectIPCounters.emitSeq.Load(),
		"connect_ip_ptb_rx_total":                     connectIPCounters.ptbRxTotal.Load(),
		"connect_ip_packet_write_fail_total":          connectIPCounters.packetWriteFailTotal.Load(),
		"connect_ip_packet_write_fail_reason_total":   writeReasons,
		"connect_ip_packet_read_exit_total":           connectIPCounters.packetReadExitTotal.Load(),
		"connect_ip_packet_read_drop_reason_total":    readReasons,
		"connect_ip_packet_tx_total":                  connectIPCounters.packetTxTotal.Load(),
		"connect_ip_packet_rx_total":                  connectIPCounters.packetRxTotal.Load(),
		"connect_ip_bytes_tx_total":                   connectIPCounters.bytesTxTotal.Load(),
		"connect_ip_bytes_rx_total":                   connectIPCounters.bytesRxTotal.Load(),
		"connect_ip_netstack_read_inject_total":       connectIPCounters.netstackReadInjectTotal.Load(),
		"connect_ip_netstack_read_drop_invalid_total": connectIPCounters.netstackReadDropInvalidTotal.Load(),
		"connect_ip_netstack_write_dequeued_total":    connectIPCounters.netstackWriteDequeuedTotal.Load(),
		"connect_ip_netstack_write_attempt_total":     connectIPCounters.netstackWriteAttemptTotal.Load(),
		"connect_ip_netstack_write_success_total":     connectIPCounters.netstackWriteSuccessTotal.Load(),
		"connect_ip_bypass_listenpacket_total":        connectIPCounters.bypassListenPacketTotal.Load(),
		"connect_ip_open_session_total":               connectIPCounters.openSessionTotal.Load(),
		"connect_ip_engine_ingress_total":             connectIPCounters.engineIngressTotal.Load(),
		"connect_ip_engine_classified_total":          connectIPCounters.engineClassifiedTotal.Load(),
		"connect_ip_engine_drop_total":                connectIPCounters.engineDropTotal.Load(),
		"connect_ip_engine_drop_reason_total":         engineDropReasons,
		"connect_ip_engine_icmp_feedback_total":       connectIPCounters.engineICMPFeedbackTotal.Load(),
		"connect_ip_engine_pmtu_update_total":         connectIPCounters.enginePMTUUpdateTotal.Load(),
		"connect_ip_engine_pmtu_update_reason_total":  pmtuUpdateReasons,
		"connect_ip_engine_effective_udp_payload":     connectIPCounters.engineEffectiveUDPPayload.Load(),
		"connect_ip_bridge_udp_tx_attempt_total":      connectIPCounters.bridgeUDPTXAttemptTotal.Load(),
		"connect_ip_bridge_build_total":               connectIPCounters.bridgeBuildTotal.Load(),
		"connect_ip_bridge_write_enter_total":         connectIPCounters.bridgeWriteEnterTotal.Load(),
		"connect_ip_bridge_write_chunk_total":         connectIPCounters.bridgeWriteChunkTotal.Load(),
		"connect_ip_bridge_write_ok_total":            connectIPCounters.bridgeWriteOkTotal.Load(),
		"connect_ip_bridge_write_err_total":           connectIPCounters.bridgeWriteErrTotal.Load(),
		"connect_ip_bridge_write_err_reason_total":    bridgeWriteErrReasons,
		"connect_ip_session_reset_total":              reasons,
		"connect_ip_capsule_unknown_total":            connectip.UnknownCapsuleTotal(),
		"connect_ip_datagram_context_unknown_total":   connectip.UnknownContextDatagramTotal(),
		"connect_ip_datagram_malformed_total":         connectip.MalformedDatagramTotal(),
		"connect_ip_policy_drop_icmp_total":           connectip.PolicyDropICMPTotal(),
		"connect_ip_policy_drop_icmp_attempt_total":   connectip.PolicyDropICMPAttemptTotal(),
		"connect_ip_policy_drop_icmp_reason_total":    policyDropICMPReasonSnapshot(),
		// Process-wide HTTP/3 per-stream DATAGRAM queue drops (patched quic-go http3); correlates with bulk/burst loss.
		"http3_stream_datagram_queue_drop_total":     http3.StreamDatagramQueueDropTotal(),
		"http3_stream_datagram_recv_closed_drop_total": http3.StreamDatagramRecvClosedDropTotal(),
		// Process-wide drops for DATAGRAM frames mapped to unknown HTTP/3 stream IDs.
		// Indicates mapping/lifecycle mismatches without stopping the receive loop.
		"http3_datagram_unknown_stream_drop_total": http3.UnknownStreamDatagramDropTotal(),
		// QUIC conn-level DATAGRAM receive-queue overflow (patched quic-go datagram_queue.go).
		"quic_datagram_rcv_queue_drop_total": quic.DatagramReceiveQueueDropTotal(),
		// QUIC packet-packer DATAGRAM oversize drops (frame too large for remaining packet budget AND no co-packed ACK).
		// Silent TX-side loss bucket previously invisible to OBS; sub-percent CONNECT-IP loss without queue drops typically lands here.
		"quic_datagram_packer_oversize_drop_total": quic.DatagramPackerOversizeDropTotal(),
	}
	if fn := connectIPServerParseDropSupplier; fn != nil {
		out["connect_ip_server_parse_drop_total"] = fn()
	}
	return out
}

func emitConnectIPObservabilityEvent(reason string) {
	snapshot := ConnectIPObservabilitySnapshot()
	snapshot["connect_ip_emit_seq"] = connectIPCounters.emitSeq.Add(1)
	snapshot["event_reason"] = reason
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		log.Printf("CONNECT_IP_OBS marshal_error=%v", err)
		return
	}
	log.Printf("CONNECT_IP_OBS %s", encoded)
}

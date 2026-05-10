package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
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
	"golang.org/x/net/http2"
)

// cloudflareLegacyH3DatagramSettingID is the SETTINGS identifier quiche/Cloudflare WARP still ship for legacy H3 datagrams (see usque).
const cloudflareLegacyH3DatagramSettingID uint64 = 0x276

// Above 1200: room for CONNECT-IP (context id + full IPv4/UDP datagram @ 1152 B payload)
// inside HTTP/3 DATGRAM without quic_datagram_packer_oversize_drop spikes on Docker Desktop bulk.
const defaultUDPInitialPacketSize uint16 = 1420

// connectIPUDPWriteBufPool backs CONNECT-IP UDP bridge egress builds (IPv4+UDP+payload).
// Avoids a process-global mutex on connectIPUDPPacketConn for buffer reuse; WritePacket copies before return.
var connectIPUDPWriteBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 2048)
		return &b
	},
}

const defaultConnectIPDatagramCeilingMax = 1500

// CONNECT-IP UDP bridge: max application UDP payload per IPv4 datagram before WritePacket.
// 1152 matches conventional MASQUE CONNECT-IP max UDP payload (aligned with sing-box CONNECT-IP path).
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
	// httpLayer mirrors coreSession udp overlay: option.MasqueHTTPLayerH3 ⇒ post-handshake
	// READ/WRITE errors are tagged "masque h3 dataplane connect-udp …" so nested QUIC/http3 text
	// does not imply http_layer_fallback (parity H2+h2ConnectUDPPacketConn, CONNECT-stream streamConn).
	httpLayer string
}

func newMasqueUDPDatagramSplitConn(pc net.PacketConn, maxPayload int, httpLayer string) *masqueUDPDatagramSplitConn {
	return &masqueUDPDatagramSplitConn{PacketConn: pc, maxPayload: maxPayload, httpLayer: httpLayer}
}

func (c *masqueUDPDatagramSplitConn) wrapUDPConnectDataplaneErr(op string, err error) error {
	if err == nil {
		return nil
	}
	if c == nil || c.httpLayer != option.MasqueHTTPLayerH3 {
		return err
	}
	return fmt.Errorf("masque h3 dataplane connect-udp %s: %w", op, err)
}

func (c *masqueUDPDatagramSplitConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	return n, addr, c.wrapUDPConnectDataplaneErr("read", err)
}

func (c *masqueUDPDatagramSplitConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	// coreSession always sets masqueUDPWriteMax ≥ 512; misconstructed wrappers must not slice
	// with non-positive maxPayload (underflowing end index) or spin on zero-sized chunks.
	max := c.maxPayload
	if c.httpLayer == option.MasqueHTTPLayerH2 && max > h2ConnectUDPMaxUDPPayloadPerDatagramCapsule {
		// CONNECT-UDP over HTTP/2: each tunnel chunk must fit RFC 9297 DATAGRAM capsule body
		// (context id byte + UDP bytes) within h2ConnectUDPMaxCapsulePayload if lower WriteTo lacks splitting.
		max = h2ConnectUDPMaxUDPPayloadPerDatagramCapsule
	}
	if max <= 0 {
		n, err := c.PacketConn.WriteTo(p, addr)
		return n, c.wrapUDPConnectDataplaneErr("write", err)
	}
	if len(p) <= max {
		n, err := c.PacketConn.WriteTo(p, addr)
		return n, c.wrapUDPConnectDataplaneErr("write", err)
	}
	// One outer fragment = at most max bytes of application payload per tunnel datagram.
	// If the lower PacketConn returns n < len(fragment) without error, keep writing the
	// remainder of that fragment before starting the next (avoids mis-aligned chunks).
	total := 0
	for total < len(p) {
		end := total + max
		if end > len(p) {
			end = len(p)
		}
		pos := total
		for pos < end {
			n, err := c.PacketConn.WriteTo(p[pos:end], addr)
			pos += n
			if err != nil {
				return pos, c.wrapUDPConnectDataplaneErr("write", err)
			}
			if n == 0 {
				return pos, c.wrapUDPConnectDataplaneErr("write", fmt.Errorf("masque: zero-length WriteTo on CONNECT-UDP split"))
			}
		}
		total = pos
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

// masqueWarpCloudflareQUICBase returns QUIC defaults aligned with Diniboy1123/usque cmd/socks:
// default initial-packet-size 0 (quic-go default first flight + path MTU) and keepalive-period 30s.
// Avoids forcing InitialPacketSize=1420 together with warp_masque's custom QUIC dial wrapper, which can
// contribute to QUIC/TLS failures against real Cloudflare MASQUE edges.
func masqueWarpCloudflareQUICBase() *quic.Config {
	return &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 30 * time.Second,
	}
}

func masqueQUICConfigForDial(opts ClientOptions) *quic.Config {
	if len(opts.WarpMasqueClientCert.Certificate) > 0 {
		return masquePacketPlaneQUICConfig(masqueWarpCloudflareQUICBase())
	}
	return newMasqueQUICConfig()
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

// HTTPLayerCacheDialIdentity is the live MASQUE TLS edge identity for TTL cache keys under http_layer:auto.
type HTTPLayerCacheDialIdentity struct {
	HopTag           string
	Server           string
	Port             uint16
	DialPortOverride uint16 // when non-zero, replaces Port when forming the cache key (see EffectiveMasque bootstrap)
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
	ErrQUICPacketConnContract = errors.New("quic transport packetconn contract violation")
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
	quicTransportTierByPath      map[string]uint64
	quicTransportTypeByPath      map[string]string
	quicTransportBufferTuningOK  uint64
	quicTransportBufferTuningNOK uint64
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
	quicTransportTierByPath:  make(map[string]uint64),
	quicTransportTypeByPath:  make(map[string]string),
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
	Tag    string
	Server string
	// DialPeer, when non-empty, is the UDP/QUIC packet destination host (often a literal CF edge IP).
	// Masque HTTPS templates and default URIs continue to use Server (typically a hostname).
	DialPeer                 string
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
	TCPDial                  MasqueTCPDialFunc
	MasqueEffectiveHTTPLayer string
	HTTPLayerFallback        bool
	HTTPLayerSuccess         func(layer string, id HTTPLayerCacheDialIdentity)
	// WarpMasque fields: Cloudflare consumer MASQUE / usque dataplane parity (optional for generic masque).
	WarpMasqueClientCert        tls.Certificate
	WarpMasquePinnedPubKey      *ecdsa.PublicKey
	WarpMasqueLegacyH3Extras    bool
	WarpConnectIPProtocol       string
	WarpMasqueDeviceBearerToken string // WARP profile auth_token; see warpMasqueConnectStreamBearerToken
}

// warpMasqueConnectStreamBearerToken chooses Authorization Bearer for CONNECT-stream only.
// Explicit server_token wins; some Cloudflare edges expect the WARP device access token on TCP CONNECT
// when org policy tokens are absent (CONNECT-UDP/CONNECT-IP paths may omit it via mTLS).
func warpMasqueConnectStreamBearerToken(opts ClientOptions) string {
	if t := strings.TrimSpace(opts.ServerToken); t != "" {
		return t
	}
	return strings.TrimSpace(opts.WarpMasqueDeviceBearerToken)
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

// MasqueTCPDialFunc wires outbound TCP (+TLS handshake target) for the HTTP/2 MASQUE overlay.
type MasqueTCPDialFunc func(ctx context.Context, network, address string) (net.Conn, error)

type quicPacketConnPolicy string

const (
	quicPacketConnPolicyStrict     quicPacketConnPolicy = "strict"
	quicPacketConnPolicyPermissive quicPacketConnPolicy = "permissive"
)

type quicTransportPacketConnTier string

const (
	quicTransportPacketConnTierA quicTransportPacketConnTier = "TierA"
	quicTransportPacketConnTierB quicTransportPacketConnTier = "TierB"
)

func masqueQUICPacketConnPolicy() quicPacketConnPolicy {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("MASQUE_QUIC_PACKET_CONN_POLICY"))) {
	case "":
		return quicPacketConnPolicyPermissive
	case string(quicPacketConnPolicyPermissive):
		return quicPacketConnPolicyPermissive
	default:
		return quicPacketConnPolicyStrict
	}
}

func quicPacketConnHasTierACapabilities(c net.PacketConn) (ok bool, connType string, missing []string) {
	connType = fmt.Sprintf("%T", c)
	if c == nil {
		return false, connType, []string{"packet_conn_nil"}
	}
	if _, yes := c.(interface{ SetReadBuffer(bytes int) error }); !yes {
		missing = append(missing, "SetReadBuffer")
	}
	if _, yes := c.(interface{ SetWriteBuffer(bytes int) error }); !yes {
		missing = append(missing, "SetWriteBuffer")
	}
	if _, yes := c.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); !yes {
		missing = append(missing, "SyscallConn")
	}
	return len(missing) == 0, connType, missing
}

func ValidateQUICTransportPacketConn(c net.PacketConn, path string) error {
	ok, connType, missing := quicPacketConnHasTierACapabilities(c)
	if ok {
		recordQUICTransportPacketConn(path, quicTransportPacketConnTierA, connType, true)
		return nil
	}
	recordQUICTransportPacketConn(path, quicTransportPacketConnTierB, connType, false)
	details := strings.Join(missing, ",")
	policy := masqueQUICPacketConnPolicy()
	if policy == quicPacketConnPolicyPermissive {
		log.Printf("masque quic packetconn degraded mode path=%s policy=%s conn_type=%s missing=%s", path, policy, connType, details)
		return nil
	}
	return errors.Join(
		ErrQUICPacketConnContract,
		fmt.Errorf("path=%s policy=%s conn_type=%s missing=%s", path, policy, connType, details),
	)
}

func recordQUICTransportPacketConn(path string, tier quicTransportPacketConnTier, connType string, bufferTuningOK bool) {
	connectIPCounters.mu.Lock()
	defer connectIPCounters.mu.Unlock()
	key := fmt.Sprintf("%s|%s", path, tier)
	connectIPCounters.quicTransportTierByPath[key]++
	connectIPCounters.quicTransportTypeByPath[path] = connType
	if bufferTuningOK {
		connectIPCounters.quicTransportBufferTuningOK++
	} else {
		connectIPCounters.quicTransportBufferTuningNOK++
	}
}

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

// IPPacketSessionWithContext is an optional context-aware packet reader for the CONNECT-IP
// plane so read deadlines and cancellation propagate; plain ReadPacket may block without it.
type IPPacketSessionWithContext interface {
	ReadPacketWithContext(ctx context.Context, buffer []byte) (int, error)
}

type DirectClientFactory struct{}

func (f DirectClientFactory) NewSession(ctx context.Context, options ClientOptions) (ClientSession, error) {
	tcpTransport := normalizeTCPTransport(options.TCPTransport)
	return &directSession{
		dialer:       net.Dialer{},
		tcpTransport: tcpTransport,
		capabilities: CapabilitySet{ConnectUDP: true, ConnectIP: false, ConnectTCP: tcpTransport == option.MasqueTCPTransportConnectStream},
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
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	default:
	}
	switch s.tcpTransport {
	case option.MasqueTCPTransportConnectIP:
		return nil, errors.Join(ErrTCPOverConnectIP, errors.New("connect_ip is TUN packet-plane only"))
	case option.MasqueTCPTransportConnectStream:
		// Plain direct TCP via net.Dialer below.
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
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	default:
	}
	if !s.capabilities.ConnectUDP {
		return nil, E.New("masque backend does not support CONNECT-UDP")
	}
	return net.ListenPacket("udp", "")
}

func (s *directSession) OpenIPSession(ctx context.Context) (IPPacketSession, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	default:
	}
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
	tm := strings.ToLower(strings.TrimSpace(options.TransportMode))
	tcpCapable := tcpTransport == option.MasqueTCPTransportConnectStream ||
		(tcpTransport == option.MasqueTCPTransportConnectIP && tm == option.MasqueTransportModeConnectIP)
	effectiveCeiling := int(options.ConnectIPDatagramCeiling)
	if effectiveCeiling <= 0 {
		effectiveCeiling = defaultConnectIPDatagramCeilingMax
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
	// Same 1152 B app-payload ceiling as CONNECT-IP UDP bridge (RFC MASQUE expectations).
	if masqueUDPWriteMax > connectIPUDPWriteHardCap {
		masqueUDPWriteMax = connectIPUDPWriteHardCap
	}
	udpLayer := strings.ToLower(strings.TrimSpace(options.MasqueEffectiveHTTPLayer))
	if udpLayer != option.MasqueHTTPLayerH2 {
		udpLayer = option.MasqueHTTPLayerH3
	}
	quicStyleDatagrams := udpLayer != option.MasqueHTTPLayerH2
	cs := &coreSession{
		options:                  options,
		templateUDP:              templateUDP,
		templateIP:               templateIP,
		templateTCP:              templateTCP,
		capabilities:             CapabilitySet{ExtendedConnect: true, Datagrams: quicStyleDatagrams, CapsuleProtocol: true, ConnectUDP: true, ConnectIP: true, ConnectTCP: tcpCapable},
		hopOrder:                 resolveHopOrder(options.Hops),
		connectIPDatagramCeiling: effectiveCeiling,
		masqueUDPWriteMax:        masqueUDPWriteMax,
		connectIPPMTUState:       newConnectIPPMTUState(initialPayload, 512, initialPayload),
		httpLayerFallback:        options.HTTPLayerFallback,
	}
	cs.udpHTTPLayer.Store(udpLayer)
	return cs, nil
}

func newConnectIPPMTUState(currentPayload, minPayload, maxPayload int) *connectIPPMTUState {
	s := &connectIPPMTUState{}
	s.currentPayload.Store(int64(currentPayload))
	s.minPayload.Store(int64(minPayload))
	s.maxPayload.Store(int64(maxPayload))
	return s
}

type coreSession struct {
	mu                   sync.Mutex
	options              ClientOptions
	udpClient            *qmasque.Client
	h2UdpTransport       *http2.Transport
	h2UdpMu              sync.Mutex
	httpLayerFallback    bool
	httpFallbackConsumed atomic.Bool
	udpHTTPLayer         atomic.Value // "h3" | "h2"; synchronized overlay for CONNECT-UDP / CONNECT-stream / CONNECT-IP
	udpDial              func(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error)
	// h2UDPConnectHook substitutes H2 CONNECT-UDP dial for package tests (nil in production).
	h2UDPConnectHook func(ctx context.Context, template *uritemplate.Template, target string) (net.PacketConn, error)
	// dialConnectIPAttemptHook substitutes production CONNECT-IP dial for package tests (nil in production).
	dialConnectIPAttemptHook func(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error)
	// listenPacketPreResolveDestinationHook runs after releasing mu on the connect_udp path (tests only).
	listenPacketPreResolveDestinationHook func()
	// listenPacketPostOpenIPSessionUnlockHook runs after Unlock on successful openIPSessionLocked (connect_ip path, tests only).
	listenPacketPostOpenIPSessionUnlockHook func()
	// listenPacketPreChainEndReturnHook runs before returning UDP dial failure when no more hops (connect_udp chain end, tests only).
	listenPacketPreChainEndReturnHook func()
	// dialTCPStreamPreAdvanceHopHook runs after ctx-alive check and before hop advance (tests only; simulates cancel before advanceHop).
	dialTCPStreamPreAdvanceHopHook func()
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
	tcpNetstack              TCPNetstack

	// Single-consumer CONNECT-IP ingress (see connect_ip_ingress.go).
	connectIPIngressSubsMu  sync.Mutex
	udpIngressSubscribers   []*udpIngressSubscriber
	connectIPIngressLoopMu  sync.Mutex
	connectIPIngressRunning atomic.Bool
	connectIPIngressCancel  context.CancelFunc
	connectIPIngressWG      sync.WaitGroup
	ipIngressPacketReader   atomic.Pointer[connectIPPacketSession]
	ingressTCPNetstack      atomic.Pointer[connectIPTCPNetstack]
}

type connectIPUDPPacketConn struct {
	session          IPPacketSession
	core             *coreSession
	ingressSub       *udpIngressSubscriber
	ingressUnregOnce sync.Once
	localV4          netip.Addr
	localBind        *net.UDPAddr
	pmtuState        *connectIPPMTUState
	deadlines        connDeadlines
	readMu           sync.Mutex
	readBuffer       []byte
	readScratchAddr  net.UDPAddr
	closed           atomic.Bool
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
	select {
	case <-ctx.Done():
		s.clearHTTPFallbackConsumedAfterGivingUp()
		return nil, context.Cause(ctx)
	default:
	}
	switch normalizeTCPTransport(s.options.TCPTransport) {
	case option.MasqueTCPTransportConnectStream:
		conn, err := s.dialTCPStream(ctx, destination)
		if err == nil {
			recordTCPDialSuccess()
			return conn, nil
		}
		if tcpMasqueDirectFallbackEnabled(s.options) && isTCPMasqueDirectFallbackEligible(err, ctx) {
			if host, hostErr := resolveDestinationHost(destination); hostErr == nil {
				tcpTracef("masque tcp masque_or_direct+fallback=direct_explicit: CONNECT-stream failed, trying direct tcp host=%s port=%d", host, destination.Port)
			} else {
				tcpTracef("masque tcp masque_or_direct+fallback=direct_explicit: CONNECT-stream failed, direct tcp host resolution failed err=%v", hostErr)
			}
			recordTCPFallback()
			conn2, dirErr := s.dialDirectTCP(ctx, network, destination)
			if dirErr != nil {
				recordTCPDialFailure()
				recordTCPDialErrorClass(dirErr)
				return nil, dirErr
			}
			recordTCPDialSuccess()
			return conn2, nil
		}
		recordTCPDialFailure()
		recordTCPDialErrorClass(err)
		return nil, err
	case option.MasqueTCPTransportConnectIP:
		if !strings.EqualFold(strings.TrimSpace(s.options.TransportMode), option.MasqueTransportModeConnectIP) {
			err := errors.Join(ErrTCPOverConnectIP, errors.New("tcp_transport connect_ip requires transport_mode connect_ip"))
			recordTCPDialFailure()
			recordTCPDialErrorClass(err)
			return nil, err
		}
		conn, err := s.dialConnectIPTCP(ctx, destination)
		if err == nil {
			recordTCPDialSuccess()
			return conn, nil
		}
		if tcpMasqueDirectFallbackEnabled(s.options) && isTCPMasqueDirectFallbackEligible(err, ctx) {
			recordTCPFallback()
			conn2, dirErr := s.dialDirectTCP(ctx, network, destination)
			if dirErr != nil {
				recordTCPDialFailure()
				recordTCPDialErrorClass(dirErr)
				return nil, dirErr
			}
			recordTCPDialSuccess()
			return conn2, nil
		}
		recordTCPDialFailure()
		recordTCPDialErrorClass(err)
		return nil, err
	default:
		recordTCPDialFailure()
		recordTCPDialErrorClass(ErrTCPPathNotImplemented)
		return nil, ErrTCPPathNotImplemented
	}
}

// releaseOpenedConnectIPSessionIfAbandoned tears down CONNECT-IP plane state when openIPSessionLocked
// succeeded but the caller must return an error before the consumer receives a net.PacketConn (e.g.
// context canceled after Unlock). Without this, ipConn would remain attached while the caller saw
// failure — leaking the tunnel and contradicting the next ListenPacket/OpenIPSession attempt.
// Caller must not hold s.mu.
func (s *coreSession) releaseOpenedConnectIPSessionIfAbandoned() {
	s.stopConnectIPIngressForClose()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ipIngressPacketReader.Store(nil)
	s.ingressTCPNetstack.Store(nil)
	if s.tcpNetstack != nil {
		_ = s.tcpNetstack.Close()
		s.tcpNetstack = nil
	}
	if s.ipConn != nil {
		_ = s.ipConn.Close()
		s.ipConn = nil
	}
	// Next openIPSessionLocked must not reuse HTTP/3 CONNECT-IP clientConn or the shared H2 pool from
	// the abandoned connect-ip.Conn (parity with teardown inside tryHTTPFallbackSwitchLockedAssumeMu).
	s.resetIPH3TransportLockedAssumeMu()
	s.resetH2UDPTransportLockedAssumeMu()
}

func (s *coreSession) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	select {
	case <-ctx.Done():
		s.clearHTTPFallbackConsumedAfterGivingUp()
		return nil, context.Cause(ctx)
	default:
	}
	s.mu.Lock()
	if strings.EqualFold(strings.TrimSpace(s.options.TransportMode), option.MasqueTransportModeConnectIP) {
		ipSession, err := s.openIPSessionLocked(ctx)
		s.mu.Unlock()
		if err != nil {
			return nil, err
		}
		if hook := s.listenPacketPostOpenIPSessionUnlockHook; hook != nil {
			hook()
		}
		select {
		case <-ctx.Done():
			s.clearHTTPFallbackConsumedAfterGivingUp()
			s.releaseOpenedConnectIPSessionIfAbandoned()
			return nil, context.Cause(ctx)
		default:
		}
		return newConnectIPUDPPacketConn(ctx, ipSession, s), nil
	}
	s.mu.Unlock()

	if hook := s.listenPacketPreResolveDestinationHook; hook != nil {
		hook()
	}
	select {
	case <-ctx.Done():
		s.clearHTTPFallbackConsumedAfterGivingUp()
		return nil, context.Cause(ctx)
	default:
	}

	targetHost, err := resolveDestinationHost(destination)
	if err != nil {
		return nil, err
	}
	target := net.JoinHostPort(targetHost, strconv.Itoa(int(destination.Port)))

	s.mu.Lock()
	if !s.capabilities.ConnectUDP {
		s.mu.Unlock()
		return nil, E.New("masque backend does not support CONNECT-UDP")
	}
	if s.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
		if s.udpClient == nil {
			s.udpClient = s.newUDPClient()
		}
	}
	udpClient := s.udpClient
	templateUDP := s.templateUDP
	s.mu.Unlock()

	conn, err := s.dialUDPAddr(ctx, udpClient, templateUDP, target)
	if err != nil && s.tryHTTPFallbackSwitch(err) {
		s.mu.Lock()
		udpClient, templateUDP = s.wireMasqueUDPClientForOverlayLocked()
		s.mu.Unlock()
		conn, err = s.dialUDPAddr(ctx, udpClient, templateUDP, target)
		if err == nil {
			return newMasqueUDPDatagramSplitConn(conn, s.masqueUDPWriteMax, s.currentUDPHTTPLayer()), nil
		}
	}
	if err != nil {
		// first retry: same hop, force client re-dial
		s.mu.Lock()
		if s.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
			if s.udpClient == udpClient && s.udpClient != nil {
				_ = s.udpClient.Close()
				s.udpClient = s.newUDPClient()
			} else if s.udpClient == nil {
				s.udpClient = s.newUDPClient()
			}
		} else {
			s.resetH2UDPTransportLockedAssumeMu()
		}
		udpClient = s.udpClient
		templateUDP = s.templateUDP
		s.mu.Unlock()

		conn, err = s.dialUDPAddr(ctx, udpClient, templateUDP, target)
		if err == nil {
			return newMasqueUDPDatagramSplitConn(conn, s.masqueUDPWriteMax, s.currentUDPHTTPLayer()), nil
		}

		// Same-hop QUIC reconnect attempt can expose a handshake fault only after churn; mirror the
		// fallback opportunity that exists on the first dial and inside the advanced-hop loop so we
		// don't skip H3↔H2 before wasting a hop pivot.
		if err != nil && s.tryHTTPFallbackSwitch(err) {
			s.mu.Lock()
			udpClient, templateUDP = s.wireMasqueUDPClientForOverlayLocked()
			s.mu.Unlock()
			conn, err = s.dialUDPAddr(ctx, udpClient, templateUDP, target)
			if err == nil {
				return newMasqueUDPDatagramSplitConn(conn, s.masqueUDPWriteMax, s.currentUDPHTTPLayer()), nil
			}
		}

		s.mu.Lock()
		for {
			if !s.advanceHop() {
				s.mu.Unlock()
				s.clearHTTPFallbackConsumedAfterGivingUp()
				if s.listenPacketPreChainEndReturnHook != nil {
					s.listenPacketPreChainEndReturnHook()
				}
				if ctx.Err() != nil {
					return nil, errors.Join(err, context.Cause(ctx))
				}
				return nil, err
			}
			if resetErr := s.resetHopTemplates(); resetErr != nil {
				s.mu.Unlock()
				s.clearHTTPFallbackConsumedAfterGivingUp()
				if ctx.Err() != nil {
					return nil, errors.Join(resetErr, context.Cause(ctx))
				}
				return nil, resetErr
			}
			if s.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
				if s.udpClient == nil {
					s.udpClient = s.newUDPClient()
				}
			}
			udpClient = s.udpClient
			templateUDP = s.templateUDP
			s.mu.Unlock()
			conn, err = s.dialUDPAddr(ctx, udpClient, templateUDP, target)
			if err != nil && s.tryHTTPFallbackSwitch(err) {
				s.mu.Lock()
				udpClient, templateUDP = s.wireMasqueUDPClientForOverlayLocked()
				s.mu.Unlock()
				conn, err = s.dialUDPAddr(ctx, udpClient, templateUDP, target)
			}
			if err == nil {
				return newMasqueUDPDatagramSplitConn(conn, s.masqueUDPWriteMax, s.currentUDPHTTPLayer()), nil
			}
			s.mu.Lock()
		}
	}
	return newMasqueUDPDatagramSplitConn(conn, s.masqueUDPWriteMax, s.currentUDPHTTPLayer()), nil
}

func (s *coreSession) currentUDPHTTPLayer() string {
	v, _ := s.udpHTTPLayer.Load().(string)
	switch strings.ToLower(strings.TrimSpace(v)) {
	case option.MasqueHTTPLayerH2:
		return option.MasqueHTTPLayerH2
	default:
		return option.MasqueHTTPLayerH3
	}
}

func (s *coreSession) htLayerCacheDialIdentity() HTTPLayerCacheDialIdentity {
	var hopTag string
	if len(s.hopOrder) > 0 && s.hopIndex >= 0 && s.hopIndex < len(s.hopOrder) {
		hopTag = strings.TrimSpace(s.hopOrder[s.hopIndex].Tag)
	}
	return HTTPLayerCacheDialIdentity{
		HopTag: hopTag,
		Server: strings.TrimSpace(s.options.Server),
		Port:   s.options.ServerPort,
	}
}

// maybeRecordHTTPLayerCacheSuccess forwards a working h2/h3 choice to protocol/masque.RecordMasqueHTTPLayerSuccess.
// EffectiveMasqueClientHTTPLayer only consults the chain entry hop (empty Via), not inner hops after advanceHop.
// Recording while hopIndex>0 wrote unused keys (cold start never looks them up) and could confuse operators;
// inner-hop overlay state is intentionally not persisted across process restarts until entry succeeds.
func (s *coreSession) maybeRecordHTTPLayerCacheSuccess(layer string) {
	if s.options.HTTPLayerSuccess == nil {
		return
	}
	if len(s.hopOrder) > 0 && s.hopIndex > 0 {
		return
	}
	s.options.HTTPLayerSuccess(layer, s.htLayerCacheDialIdentity())
}

// wireMasqueUDPClientForOverlayLocked rebuilds QUIC CONNECT-UDP client or clears it when the
// overlay is H2; caller must hold s.mu (udpHTTPLayer was updated by tryHTTPFallbackSwitch).
func (s *coreSession) resetIPH3TransportLockedAssumeMu() {
	if s.ipHTTP != nil {
		s.ipHTTP.Close()
		if s.tcpHTTP == s.ipHTTP {
			s.tcpHTTP = nil
		}
		s.ipHTTP = nil
	}
	s.ipHTTPConn = nil
}

func (s *coreSession) wireMasqueUDPClientForOverlayLocked() (*qmasque.Client, *uritemplate.Template) {
	if s.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2 {
		if s.udpClient == nil {
			s.udpClient = s.newUDPClient()
		}
	} else if s.udpClient != nil {
		_ = s.udpClient.Close()
		s.udpClient = nil
	}
	return s.udpClient, s.templateUDP
}

func (s *coreSession) tryHTTPFallbackSwitch(err error) bool {
	s.mu.Lock()
	ok := s.tryHTTPFallbackSwitchLockedAssumeMu(err)
	s.mu.Unlock()
	return ok
}

func (s *coreSession) tryHTTPFallbackSwitchLockedAssumeMu(err error) bool {
	if !s.httpLayerFallback || err == nil || !IsMasqueHTTPLayerSwitchableFailure(err) {
		return false
	}
	if !s.httpFallbackConsumed.CompareAndSwap(false, true) {
		return false
	}
	cur := s.currentUDPHTTPLayer()
	var next string
	switch cur {
	case option.MasqueHTTPLayerH3:
		next = option.MasqueHTTPLayerH2
	case option.MasqueHTTPLayerH2:
		next = option.MasqueHTTPLayerH3
	default:
		s.httpFallbackConsumed.Store(false)
		return false
	}
	log.Printf("masque_http_layer_fallback tag=%s from=%s to=%s", strings.TrimSpace(s.options.Tag), cur, next)
	// CONNECT-IP / CONNECT-stream / ingress must not outlive overlay switch: udpHTTPLayer is shared.
	s.stopConnectIPIngressForClose()
	s.ipIngressPacketReader.Store(nil)
	s.ingressTCPNetstack.Store(nil)
	if s.tcpNetstack != nil {
		_ = s.tcpNetstack.Close()
		s.tcpNetstack = nil
	}
	if s.ipConn != nil {
		_ = s.ipConn.Close()
		s.ipConn = nil
	}
	if s.ipHTTP != nil {
		s.ipHTTP.Close()
		if s.tcpHTTP == s.ipHTTP {
			s.tcpHTTP = nil
		}
		s.ipHTTP = nil
		s.ipHTTPConn = nil
	}
	if s.tcpHTTP != nil {
		s.tcpHTTP.Close()
		s.tcpHTTP = nil
	}
	if s.udpClient != nil {
		_ = s.udpClient.Close()
		s.udpClient = nil
	}
	s.h2UdpMu.Lock()
	if s.h2UdpTransport != nil {
		s.h2UdpTransport.CloseIdleConnections()
		s.h2UdpTransport = nil
	}
	s.h2UdpMu.Unlock()
	s.udpHTTPLayer.Store(next)
	return true
}

// resetHTTPFallbackBudgetAfterSuccess clears the one-shot http_layer_fallback latch after a successful
// overlay handshake. tryHTTPFallbackSwitch sets the latch while reacting to a failure wave; without
// this reset, a later switchable error on the same hop could not pivot again until hop advance.
func (s *coreSession) resetHTTPFallbackBudgetAfterSuccess() {
	s.httpFallbackConsumed.Store(false)
}

// clearHTTPFallbackConsumedAfterGivingUp resets the latch when we return an error to the caller so the
// next ListenPacket/OpenIPSession/DialContext/dialTCPStream attempt gets a fresh H3↔H2 pivot budget. Without this,
// a consumed latch from a totally failed handshake wave could block overlay fallback on retries at the
// same hop (tryHTTPFallbackSwitch uses CompareAndSwap on the latch).
func (s *coreSession) clearHTTPFallbackConsumedAfterGivingUp() {
	s.httpFallbackConsumed.Store(false)
}

// masqueUDPExpandedURLAuthority returns the https URL host (authority) from the CONNECT-UDP template expansion
// for observability logs; empty if template/target cannot be expanded.
func masqueUDPExpandedURLAuthority(template *uritemplate.Template, target string) string {
	if template == nil {
		return ""
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return ""
	}
	expanded, err := template.Expand(uritemplate.Values{
		"target_host": uritemplate.String(host),
		"target_port": uritemplate.String(port),
	})
	if err != nil {
		return ""
	}
	u, err := url.Parse(expanded)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

// masqueUDPConnectObservabilityFields returns target and dial for CONNECT-UDP masque_http_layer_* logs
// (aligned with attempt lines; no secrets).
func masqueUDPConnectObservabilityFields(options ClientOptions, template *uritemplate.Template, target string) (logTarget, dialAddr string) {
	portNum := int(options.ServerPort)
	if portNum <= 0 {
		portNum = 443
	}
	dialAddr = masqueDialTarget(masqueQuicDialCandidateHost(options), portNum)
	logTarget = masqueUDPExpandedURLAuthority(template, target)
	if logTarget == "" {
		logTarget = target
	}
	return logTarget, dialAddr
}

// masqueConnectIPOverlayDialAddr returns the TCP/TLS dial peer for CONNECT-IP overlay logs (H2/H3).
func masqueConnectIPOverlayDialAddr(options ClientOptions) string {
	portNum := int(options.ServerPort)
	if portNum <= 0 {
		portNum = 443
	}
	return masqueDialTarget(masqueQuicDialCandidateHost(options), portNum)
}

func (s *coreSession) dialUDPAddr(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
	// CONNECT-UDP on H2 is HTTP/2 datagram capsules; udpDial replaces only the QUIC/masque-go path when set (tests).
	if s.currentUDPHTTPLayer() == option.MasqueHTTPLayerH2 {
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		default:
		}
		if template == nil {
			return nil, ErrConnectUDPTemplateNotConfigured
		}
		logTarget, dialAddr := masqueUDPConnectObservabilityFields(s.options, template, target)
		log.Printf("masque_http_layer_attempt layer=h2 tag=%s connect_udp=1 target=%s dial=%s", strings.TrimSpace(s.options.Tag), logTarget, dialAddr)
		pc, err := s.dialUDPOverHTTP2(ctx, template, target)
		if err == nil {
			s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH2)
			log.Printf("masque_http_layer_chosen layer=h2 tag=%s connect_udp=1 target=%s dial=%s", strings.TrimSpace(s.options.Tag), logTarget, dialAddr)
			s.resetHTTPFallbackBudgetAfterSuccess()
		}
		return pc, err
	}
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	default:
	}
	if template == nil {
		return nil, ErrConnectUDPTemplateNotConfigured
	}
	logTarget, dialAddr := masqueUDPConnectObservabilityFields(s.options, template, target)
	if s.udpDial != nil {
		log.Printf("masque_http_layer_attempt layer=h3 tag=%s connect_udp=1 target=%s dial=%s", strings.TrimSpace(s.options.Tag), logTarget, dialAddr)
		pc, err := s.udpDial(ctx, client, template, target)
		if err == nil {
			s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH3)
			log.Printf("masque_http_layer_chosen layer=h3 tag=%s connect_udp=1 target=%s dial=%s", strings.TrimSpace(s.options.Tag), logTarget, dialAddr)
			s.resetHTTPFallbackBudgetAfterSuccess()
		}
		return pc, err
	}
	if client == nil {
		return nil, E.New("masque CONNECT-UDP QUIC client not initialized")
	}
	log.Printf("masque_http_layer_attempt layer=h3 tag=%s connect_udp=1 target=%s dial=%s", strings.TrimSpace(s.options.Tag), logTarget, dialAddr)
	conn, _, err := client.DialAddr(ctx, template, target)
	if err == nil {
		s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH3)
		log.Printf("masque_http_layer_chosen layer=h3 tag=%s connect_udp=1 target=%s dial=%s", strings.TrimSpace(s.options.Tag), logTarget, dialAddr)
		s.resetHTTPFallbackBudgetAfterSuccess()
	}
	return conn, err
}

func newConnectIPUDPPacketConn(ctx context.Context, session IPPacketSession, core *coreSession) net.PacketConn {
	localV4 := netip.MustParseAddr("198.18.0.1")
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
		prefixes := connectIPSession.conn.CurrentAssignedPrefixes()
		var err error
		if len(prefixes) == 0 {
			prefixCtx, cancel := context.WithTimeout(ctx, time.Second)
			prefixes, err = connectIPSession.conn.LocalPrefixes(prefixCtx)
			cancel()
		}
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
	pc := &connectIPUDPPacketConn{
		session:         session,
		localV4:         localV4,
		localBind:       &net.UDPAddr{IP: localIP, Port: 53000},
		pmtuState:       pmtuState,
		readScratchAddr: net.UDPAddr{IP: make(net.IP, 0, 16)},
	}
	if core != nil {
		pc.core = core
		pc.ingressSub = core.registerUDPIngressSubscriber()
	}
	return pc
}

func (c *connectIPUDPPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	if c.deadlines.readTimeoutExceeded() {
		return 0, nil, os.ErrDeadlineExceeded
	}

	ctx := context.Background()
	if v := c.deadlines.read.Load(); v != 0 {
		if time.Now().UnixNano() > v {
			return 0, nil, os.ErrDeadlineExceeded
		}
		deadline := time.Unix(0, v)
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(context.Background(), deadline)
		defer cancel()
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.ingressSub != nil {
		for {
			if c.closed.Load() {
				return 0, nil, net.ErrClosed
			}
			if c.deadlines.readTimeoutExceeded() {
				return 0, nil, os.ErrDeadlineExceeded
			}
			select {
			case <-ctx.Done():
				return 0, nil, os.ErrDeadlineExceeded
			case raw, ok := <-c.ingressSub.ch:
				if !ok {
					return 0, nil, net.ErrClosed
				}
				connectIPCounters.engineIngressTotal.Add(1)
				payloadOff, payloadLen, src, srcPort, parseErr := parseIPv4UDPPacketOffsets(raw)
				if parseErr != nil {
					incConnectIPEngineDropReason("read_parse")
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
					if payloadLen > 0 {
						if payloadOff+payloadLen > len(raw) {
							return 0, nil, fmt.Errorf("connect-ip udp bridge: UDP payload out of read bounds (%d+%d>%d)", payloadOff, payloadLen, len(raw))
						}
						copy(p[:payloadLen], raw[payloadOff:payloadOff+payloadLen])
					}
					return payloadLen, &c.readScratchAddr, nil
				}
				return copy(p, raw[payloadOff:payloadOff+payloadLen]), &c.readScratchAddr, nil
			}
		}
	}

	var sctx IPPacketSessionWithContext
	sctx, _ = c.session.(IPPacketSessionWithContext)
	for {
		var raw []byte
		if len(p) >= connectIPUDPDirectReadMin {
			if sctx != nil {
				n, err = sctx.ReadPacketWithContext(ctx, p)
			} else {
				n, err = c.session.ReadPacket(p)
			}
			raw = p[:n]
		} else {
			rb := c.readBuffer
			if rb == nil {
				rb = make([]byte, 64*1024)
				c.readBuffer = rb
			}
			if sctx != nil {
				n, err = sctx.ReadPacketWithContext(ctx, rb)
			} else {
				n, err = c.session.ReadPacket(rb)
			}
			raw = rb[:n]
		}
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return 0, nil, os.ErrDeadlineExceeded
			}
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
			if payloadLen > 0 {
				if payloadOff+payloadLen > len(raw) {
					return 0, nil, fmt.Errorf("connect-ip udp bridge: UDP payload out of read bounds (%d+%d>%d)", payloadOff, payloadLen, len(raw))
				}
				// Compact into p[:payloadLen] using only bytes from this ReadPacket (raw), not tail of len(p) past n.
				copy(p[:payloadLen], raw[payloadOff:payloadOff+payloadLen])
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
	// RFC 768 allows zero-length UDP payloads; net.UDPConn.WriteTo("", addr) still emits a datagram.
	// Run at least one chunk when len(p)==0 (otherwise we would return (0,nil) without WritePacket — unlike H2 CONNECT-UDP).
	offset := 0
	first := true
	for first || offset < len(p) {
		first = false
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
	if c.core != nil && c.ingressSub != nil {
		c.ingressUnregOnce.Do(func() {
			c.core.unregisterUDPIngressSubscriber(c.ingressSub)
		})
	}
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

// ipv4HeaderIndicatesFragmentation reports RFC 791 More-Fragments or a non-zero fragment offset.
// Caller must ensure len(b) >= 8 and that b begins with an IPv4 header.
func ipv4HeaderIndicatesFragmentation(b []byte) bool {
	flagsFrag := binary.BigEndian.Uint16(b[6:8])
	return flagsFrag&0x1fff != 0 || flagsFrag&0x2000 != 0
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
	if ipv4HeaderIndicatesFragmentation(packet) {
		return 0, 0, netip.Addr{}, 0, errors.New("connect-ip udp bridge fragmented ipv4 is not supported for udp bridge parsing")
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
		TLSClientConfig: masqueClientTLSConfig(s.options),
		QUICConfig: applyQUICExperimentalOptions(
			masqueQUICConfigForDial(s.options),
			s.options.QUICExperimental,
		),
		QUICDial:       s.quicDialWithPolicy("client_connect_udp"),
		BearerToken:    strings.TrimSpace(s.options.ServerToken),
		LegacyH3Extras: s.options.WarpMasqueLegacyH3Extras,
	}
}

func (s *coreSession) quicDialWithPolicy(path string) QUICDialFunc {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		if s.options.QUICDial != nil {
			policy := masqueQUICPacketConnPolicy()
			if policy == quicPacketConnPolicyStrict {
				recordQUICTransportPacketConn(path, quicTransportPacketConnTierB, "custom_quic_dial", false)
				return nil, errors.Join(
					ErrQUICPacketConnContract,
					fmt.Errorf("path=%s policy=%s custom_quic_dial requires explicit degraded-mode opt-in", path, policy),
				)
			}
			recordQUICTransportPacketConn(path, quicTransportPacketConnTierB, "custom_quic_dial", false)
			log.Printf("masque quic packetconn degraded mode path=%s policy=%s conn_type=%s", path, policy, "custom_quic_dial")
			return s.options.QUICDial(ctx, addr, tlsCfg, cfg)
		}
		recordQUICTransportPacketConn(path, quicTransportPacketConnTierA, "*net.UDPConn (quic.DialAddr)", true)
		return quic.DialAddr(ctx, addr, tlsCfg, cfg)
	}
}

func (s *coreSession) OpenIPSession(ctx context.Context) (IPPacketSession, error) {
	select {
	case <-ctx.Done():
		s.clearHTTPFallbackConsumedAfterGivingUp()
		return nil, context.Cause(ctx)
	default:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.openIPSessionLocked(ctx)
}

func (s *coreSession) dialWarpConnectIPTunnel(ctx context.Context, clientConn *http3.ClientConn) (*connectip.Conn, error) {
	token := strings.TrimSpace(s.options.ServerToken)
	proto := strings.TrimSpace(s.options.WarpConnectIPProtocol)
	var conn *connectip.Conn
	var err error
	if proto != "" {
		conn, _, err = connectip.DialWithOptions(ctx, clientConn, s.templateIP, connectip.DialOptions{
			BearerToken:             token,
			ExtendedConnectProtocol: proto,
		})
	} else {
		conn, _, err = connectip.Dial(ctx, clientConn, s.templateIP, token)
	}
	return conn, err
}

func (s *coreSession) dialConnectIPAttempt(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
	if hook := s.dialConnectIPAttemptHook; hook != nil {
		conn, err := hook(ctx, useHTTP2)
		if err == nil && conn != nil {
			dialAddr := masqueConnectIPOverlayDialAddr(s.options)
			if useHTTP2 {
				s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH2)
				log.Printf("masque_http_layer_chosen layer=h2 tag=%s connect_ip=1 dial=%s", strings.TrimSpace(s.options.Tag), dialAddr)
			} else {
				s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH3)
				log.Printf("masque_http_layer_chosen layer=h3 tag=%s connect_ip=1 dial=%s", strings.TrimSpace(s.options.Tag), dialAddr)
			}
			s.resetHTTPFallbackBudgetAfterSuccess()
		}
		return conn, err
	}
	if useHTTP2 {
		select {
		case <-ctx.Done():
			s.clearHTTPFallbackConsumedAfterGivingUp()
			return nil, context.Cause(ctx)
		default:
		}
		conn, err := s.dialConnectIPHTTP2(ctx)
		if err != nil || conn == nil {
			return conn, err
		}
		s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH2)
		log.Printf("masque_http_layer_chosen layer=h2 tag=%s connect_ip=1 dial=%s", strings.TrimSpace(s.options.Tag), masqueConnectIPOverlayDialAddr(s.options))
		s.resetHTTPFallbackBudgetAfterSuccess()
		return conn, nil
	}
	select {
	case <-ctx.Done():
		s.clearHTTPFallbackConsumedAfterGivingUp()
		return nil, context.Cause(ctx)
	default:
	}
	if s.templateIP == nil {
		return nil, ErrConnectIPTemplateNotConfigured
	}
	dialAddr := masqueConnectIPOverlayDialAddr(s.options)
	log.Printf("masque_http_layer_attempt layer=h3 tag=%s connect_ip=1 dial=%s", strings.TrimSpace(s.options.Tag), dialAddr)
	clientConn, err := s.openHTTP3ClientConn(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := s.dialWarpConnectIPTunnel(ctx, clientConn)
	if err != nil {
		return nil, err
	}
	s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH3)
	log.Printf("masque_http_layer_chosen layer=h3 tag=%s connect_ip=1 dial=%s", strings.TrimSpace(s.options.Tag), dialAddr)
	s.resetHTTPFallbackBudgetAfterSuccess()
	return conn, nil
}

// dialConnectIPOnCurrentHopLocked runs the same-hop CONNECT-IP sequence used by openIPSessionLocked:
// initial dial, optional http_layer fallback pivot, H3 client churn when on overlay h3, H2 transport
// churn when on overlay h2. Caller must hold s.mu.
func (s *coreSession) dialConnectIPOnCurrentHopLocked(ctx context.Context, useHTTP2 bool) (*connectip.Conn, error) {
	conn, err := s.dialConnectIPAttempt(ctx, useHTTP2)
	if err != nil && s.tryHTTPFallbackSwitchLockedAssumeMu(err) {
		useHTTP2 = s.currentUDPHTTPLayer() == option.MasqueHTTPLayerH2
		conn, err = s.dialConnectIPAttempt(ctx, useHTTP2)
	}
	if err != nil && !useHTTP2 {
		s.resetIPH3TransportLockedAssumeMu()
		conn, err = s.dialConnectIPAttempt(ctx, false)
		if err != nil && s.tryHTTPFallbackSwitchLockedAssumeMu(err) {
			useHTTP2 = s.currentUDPHTTPLayer() == option.MasqueHTTPLayerH2
			conn, err = s.dialConnectIPAttempt(ctx, useHTTP2)
		}
	}
	if err != nil && useHTTP2 {
		s.resetH2UDPTransportLockedAssumeMu()
		conn, err = s.dialConnectIPAttempt(ctx, true)
		if err != nil && s.tryHTTPFallbackSwitchLockedAssumeMu(err) {
			useHTTP2 = s.currentUDPHTTPLayer() == option.MasqueHTTPLayerH2
			conn, err = s.dialConnectIPAttempt(ctx, useHTTP2)
		}
	}
	return conn, err
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
		s.clearHTTPFallbackConsumedAfterGivingUp()
		return nil, E.New("masque backend does not support CONNECT-IP")
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		incConnectIPWriteFailReason(classifyConnectIPErrorReason(ctxErr))
		emitConnectIPObservabilityEvent("open_ip_session_fail")
		s.clearHTTPFallbackConsumedAfterGivingUp()
		return nil, context.Cause(ctx)
	}
	if s.ipConn != nil {
		if s.ipIngressPacketReader.Load() == nil {
			s.ipIngressPacketReader.Store(&connectIPPacketSession{
				conn:            s.ipConn,
				datagramCeiling: s.connectIPDatagramCeiling,
				pmtuState:       s.connectIPPMTUState,
			})
		}
		emitConnectIPObservabilityEvent("open_ip_session_success_reuse")
		s.resetHTTPFallbackBudgetAfterSuccess()
		return &connectIPPacketSession{
			conn:            s.ipConn,
			datagramCeiling: s.connectIPDatagramCeiling,
			pmtuState:       s.connectIPPMTUState,
		}, nil
	}
	tokenSet := strings.TrimSpace(s.options.ServerToken) != ""
	useHTTP2 := s.currentUDPHTTPLayer() == option.MasqueHTTPLayerH2
	conn, err := s.dialConnectIPOnCurrentHopLocked(ctx, useHTTP2)
	if err != nil {
		log.Printf("masque connectip dial failed server=%s:%d token_set=%t err=%v", s.options.Server, s.options.ServerPort, tokenSet, err)
		// User/context cancellation is not a hop pivot: do not burn chain entries or re-dial
		// subsequent hops while the caller has already given up (parity with ListenPacket/DialContext).
		if ctx.Err() != nil {
			incConnectIPWriteFailReason(classifyConnectIPErrorReason(ctx.Err()))
			emitConnectIPObservabilityEvent("open_ip_session_fail")
			s.clearHTTPFallbackConsumedAfterGivingUp()
			return nil, context.Cause(ctx)
		}
		for s.advanceHop() {
			if resetErr := s.resetHopTemplates(); resetErr != nil {
				s.clearHTTPFallbackConsumedAfterGivingUp()
				if ctx.Err() != nil {
					return nil, errors.Join(resetErr, context.Cause(ctx))
				}
				return nil, resetErr
			}
			useHTTP2 = s.currentUDPHTTPLayer() == option.MasqueHTTPLayerH2
			conn, err = s.dialConnectIPOnCurrentHopLocked(ctx, useHTTP2)
			if err == nil {
				s.ipConn = conn
				s.ipIngressPacketReader.Store(&connectIPPacketSession{
					conn:            conn,
					datagramCeiling: s.connectIPDatagramCeiling,
					pmtuState:       s.connectIPPMTUState,
				})
				connectIPCounters.openSessionTotal.Add(1)
				setConnectIPSessionID()
				emitConnectIPObservabilityEvent("open_ip_session_success")
				return &connectIPPacketSession{
					conn:            conn,
					datagramCeiling: s.connectIPDatagramCeiling,
					pmtuState:       s.connectIPPMTUState,
				}, nil
			}
			log.Printf("masque connectip dial retry failed server=%s:%d token_set=%t err=%v", s.options.Server, s.options.ServerPort, tokenSet, err)
			// Parity with hop exhaustion / dialTCPStream: cancellation after a failed inner-hop dial
			// must not consume another hop before the next advanceHop() at loop head.
			if ctx.Err() != nil {
				incConnectIPWriteFailReason(classifyConnectIPErrorReason(err))
				emitConnectIPObservabilityEvent("open_ip_session_fail")
				s.clearHTTPFallbackConsumedAfterGivingUp()
				return nil, errors.Join(err, context.Cause(ctx))
			}
		}
		incConnectIPWriteFailReason(classifyConnectIPErrorReason(err))
		emitConnectIPObservabilityEvent("open_ip_session_fail")
		s.clearHTTPFallbackConsumedAfterGivingUp()
		if ctx.Err() != nil {
			return nil, errors.Join(err, context.Cause(ctx))
		}
		return nil, err
	}
	s.ipConn = conn
	s.ipIngressPacketReader.Store(&connectIPPacketSession{
		conn:            conn,
		datagramCeiling: s.connectIPDatagramCeiling,
		pmtuState:       s.connectIPPMTUState,
	})
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
	c := s.capabilities
	// QUIC DATAGRAM applies only to the live H3/QUIC overlay; capsule datagrams on H2 never use it.
	// After http_layer_fallback rotates H2→H3, the baseline copy from NewSession can still reflect an
	// H2-effective config (e.g. auto+TTL cache pin), so derive from currentUDPHTTPLayer, not ctor only.
	c.Datagrams = s.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2
	return c
}

func (s *coreSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	emitConnectIPObservabilityEvent("session_close_begin")
	s.stopConnectIPIngressForClose()
	if s.ipConn != nil {
		errs = append(errs, s.ipConn.Close())
		s.ipConn = nil
	}
	s.ipIngressPacketReader.Store(nil)
	s.ingressTCPNetstack.Store(nil)
	// CONNECT-IP ingress stops before teardown; tcp netstack consumes inbound via inject path only.
	if s.tcpNetstack != nil {
		_ = s.tcpNetstack.Close()
		s.tcpNetstack = nil
	}
	if s.ipHTTP != nil {
		errs = append(errs, s.ipHTTP.Close())
		if s.tcpHTTP == s.ipHTTP {
			s.tcpHTTP = nil
		}
		s.ipHTTP = nil
		s.ipHTTPConn = nil
	}
	if s.udpClient != nil {
		errs = append(errs, s.udpClient.Close())
		s.udpClient = nil
	}
	s.h2UdpMu.Lock()
	if s.h2UdpTransport != nil {
		s.h2UdpTransport.CloseIdleConnections()
		s.h2UdpTransport = nil
	}
	s.h2UdpMu.Unlock()
	if s.tcpHTTP != nil {
		errs = append(errs, s.tcpHTTP.Close())
		s.tcpHTTP = nil
	}
	emitConnectIPObservabilityEvent("session_close_end")
	return errors.Join(errs...)
}

func resolveDestinationHost(destination M.Socksaddr) (string, error) {
	// ParseSocksaddrHostPort stores the raw host string in Fqdn; leading/trailing ASCII
	// whitespace breaks net.isDomainName and made IsFqdn() false on otherwise valid names.
	fqdnTrim := strings.TrimSpace(destination.Fqdn)
	if destination.IsFqdn() {
		if fqdnTrim == "" {
			return "", errors.Join(ErrCapability, E.New("invalid destination host"))
		}
		return fqdnTrim, nil
	}
	if fqdnTrim != "" {
		stub := M.Socksaddr{Fqdn: fqdnTrim}
		if stub.IsFqdn() && !destination.Addr.IsValid() {
			return fqdnTrim, nil
		}
	}
	if destination.Addr.IsValid() {
		host := strings.TrimSpace(destination.Addr.String())
		if host == "" {
			return "", errors.Join(ErrCapability, E.New("invalid destination host"))
		}
		return host, nil
	}
	return "", errors.Join(ErrCapability, E.New("invalid destination"))
}

// masqueDialTarget keeps hostname-based dial target intact so DNS resolution strategy is delegated
// to the configured dial path (custom QUIC dialer / sing-box routing DNS), instead of forcing a
// system-level IPv4 lookup here.
func masqueDialTarget(host string, port int) string {
	host = strings.TrimSpace(host)
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func (s *coreSession) openHTTP3ClientConn(ctx context.Context) (*http3.ClientConn, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, context.Cause(ctx)
	}
	if s.ipHTTPConn != nil {
		return s.ipHTTPConn, nil
	}
	port := int(s.options.ServerPort)
	if port <= 0 {
		port = 443
	}
	target := masqueDialTarget(masqueQuicDialCandidateHost(s.options), port)
	tlsConf := masqueClientTLSConfig(s.options)
	transport := &http3.Transport{
		EnableDatagrams:    true,
		DisableCompression: true, // CONNECT-UDP/IP/stream are not gzip HTTP bodies
		TLSClientConfig:    tlsConf,
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			cfg := applyQUICExperimentalOptions(
				masqueQUICConfigForDial(s.options),
				s.options.QUICExperimental,
			)
			return s.quicDialWithPolicy("client_connect_ip")(ctx, addr, tlsCfg, cfg)
		},
	}
	applyWarpMasqueHTTP3TransportFields(transport, s.options)
	conn, err := transport.Dial(ctx, target, tlsConf, applyQUICExperimentalOptions(
		masqueQUICConfigForDial(s.options),
		s.options.QUICExperimental,
	))
	if err != nil {
		log.Printf("masque openHTTP3ClientConn failed target=%s sni=%s err=%v", target, tlsConf.ServerName, err)
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
	// DialPeer overrides the packet dial target while keeping logical Server/TLS semantics for the entry hop only.
	// After advanceHop moves past the chain entry (hopIndex > 0), stale DialPeer would send QUIC/H2 overlays to the
	// wrong socket address while CONNECT templates use inner hop.Server (warp clears DialPeer when chain-mode;
	// this keeps generic/programmatic ClientOptions defensive).
	if s.hopIndex > 0 {
		s.options.DialPeer = ""
	}
	s.stopConnectIPIngressForClose()
	s.ipIngressPacketReader.Store(nil)
	s.ingressTCPNetstack.Store(nil)
	if s.tcpNetstack != nil {
		_ = s.tcpNetstack.Close()
		s.tcpNetstack = nil
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
		if s.tcpHTTP == s.ipHTTP {
			s.tcpHTTP = nil
		}
		s.ipHTTP = nil
	}
	s.ipHTTPConn = nil
	if s.tcpHTTP != nil {
		s.tcpHTTP.Close()
		s.tcpHTTP = nil
	}
	s.h2UdpMu.Lock()
	if s.h2UdpTransport != nil {
		s.h2UdpTransport.CloseIdleConnections()
		s.h2UdpTransport = nil
	}
	s.h2UdpMu.Unlock()
	// Keep the working overlay chosen for this coreSession (including after H3↔H2 fallback).
	// Advancing hops switches edge host/port/templates; snapping back to MasqueEffectiveHTTPLayer
	// would drop a dataplane-learned HTTP stack and redo failing attempts on QUIC-only paths.
	s.httpFallbackConsumed.Store(false)
	return nil
}

func resolveTLSServerName(options ClientOptions) string {
	if sni := strings.TrimSpace(options.TLSServerName); sni != "" {
		return sni
	}
	return strings.TrimSpace(options.Server)
}

func masqueClientTLSConfig(opts ClientOptions) *tls.Config {
	cfg := &tls.Config{
		NextProtos: []string{http3.NextProtoH3},
		ServerName: resolveTLSServerName(opts),
	}
	if len(opts.WarpMasqueClientCert.Certificate) > 0 {
		cfg.Certificates = []tls.Certificate{opts.WarpMasqueClientCert}
		cfg.InsecureSkipVerify = true
		if opts.WarpMasquePinnedPubKey != nil && !opts.Insecure {
			pub := opts.WarpMasquePinnedPubKey
			cfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return fmt.Errorf("warp_masque: empty peer TLS certificate")
				}
				leaf, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return err
				}
				esk, ok := leaf.PublicKey.(*ecdsa.PublicKey)
				if !ok {
					return fmt.Errorf("warp_masque: peer TLS certificate is not ECDSA")
				}
				if !esk.Equal(pub) {
					return fmt.Errorf("warp_masque: peer TLS public key does not match Cloudflare device profile pin")
				}
				return nil
			}
		}
		if opts.Insecure {
			cfg.VerifyPeerCertificate = nil
		}
		return cfg
	}
	cfg.InsecureSkipVerify = opts.Insecure
	return cfg
}

func applyWarpMasqueHTTP3TransportFields(tr *http3.Transport, opts ClientOptions) {
	if tr == nil || !opts.WarpMasqueLegacyH3Extras {
		return
	}
	tr.AdditionalSettings = map[uint64]uint64{cloudflareLegacyH3DatagramSettingID: 1}
	tr.DisableCompression = true
}

func masqueQuicDialCandidateHost(options ClientOptions) string {
	if h := strings.TrimSpace(options.DialPeer); h != "" {
		return h
	}
	return strings.TrimSpace(options.Server)
}

func normalizeTCPTransport(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case option.MasqueTCPTransportConnectStream:
		return option.MasqueTCPTransportConnectStream
	case option.MasqueTCPTransportConnectIP:
		return option.MasqueTCPTransportConnectIP
	default:
		return option.MasqueTCPTransportAuto
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
	return errors.Is(err, ErrTCPConnectStreamFailed) || errors.Is(err, ErrTCPDial)
}

func normalizeTCPDestinationForConnectIPNetstack(ctx context.Context, destination M.Socksaddr) (M.Socksaddr, error) {
	if destination.Port == 0 {
		return M.Socksaddr{}, errors.Join(ErrTCPDial, E.New("missing destination port"))
	}
	out := destination
	if out.Addr.IsValid() {
		return out, nil
	}
	if out.IsFqdn() {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", out.Fqdn)
		if err != nil {
			return M.Socksaddr{}, errors.Join(ErrTCPDial, err)
		}
		if len(ips) == 0 {
			return M.Socksaddr{}, errors.Join(ErrTCPDial, E.New("DNS returned no addresses"))
		}
		for _, ip := range ips {
			ip = ip.Unmap()
			if ip.Is4() {
				out.Addr = ip
				out.Fqdn = ""
				return out, nil
			}
		}
		out.Addr = ips[0].Unmap()
		out.Fqdn = ""
		return out, nil
	}
	return M.Socksaddr{}, errors.Join(ErrCapability, E.New("invalid masque tcp destination"))
}

func (s *coreSession) dialConnectIPTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	select {
	case <-ctx.Done():
		s.clearHTTPFallbackConsumedAfterGivingUp()
		return nil, context.Cause(ctx)
	default:
	}
	dest, err := normalizeTCPDestinationForConnectIPNetstack(ctx, destination)
	if err != nil {
		if ctx.Err() != nil {
			s.clearHTTPFallbackConsumedAfterGivingUp()
		}
		return nil, err
	}
	s.mu.Lock()
	ipSess, err := s.openIPSessionLocked(ctx)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	netstackCreatedThisCall := false
	if s.tcpNetstack == nil {
		ns, nerr := DefaultTCPNetstackFactory.New(ctx, ipSess)
		if nerr != nil {
			recordConnectIPStackReady(false)
			s.mu.Unlock()
			s.releaseOpenedConnectIPSessionIfAbandoned()
			return nil, nerr
		}
		recordConnectIPStackReady(true)
		s.tcpNetstack = ns
		netstackCreatedThisCall = true
		if impl, ok := ns.(*connectIPTCPNetstack); ok {
			s.ingressTCPNetstack.Store(impl)
		}
		s.maybeStartConnectIPIngressLocked()
	}
	ns := s.tcpNetstack
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		s.clearHTTPFallbackConsumedAfterGivingUp()
		// Only tear down the CONNECT-IP plane if this invocation created the netstack: later TCP dials
		// reuse tcpNetstack/ipConn; cancel before DialContext must not destroy an in-service session.
		if netstackCreatedThisCall {
			s.releaseOpenedConnectIPSessionIfAbandoned()
		}
		return nil, context.Cause(ctx)
	default:
	}
	return ns.DialContext(ctx, dest)
}

func (s *coreSession) dialDirectTCP(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d := net.Dialer{}
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	default:
	}
	targetHost, err := resolveDestinationHost(destination)
	if err != nil {
		return nil, err
	}
	port := strconv.Itoa(int(destination.Port))
	addr := net.JoinHostPort(targetHost, port)
	return d.DialContext(ctx, network, addr)
}

// tcpConnectStreamErrMayBenefitFromNextHop is true for overlay/network/handshake faults where advancing
// hopOrder might help. False for ErrCapability (invalid Socksaddr from resolveDestinationHost,
// TCP template Expand/Parse, etc.) — parity with ListenPacket not consuming hops on resolve errors.
func tcpConnectStreamErrMayBenefitFromNextHop(err error) bool {
	return err != nil && !errors.Is(err, ErrCapability)
}

// tcpMasqueConnectStreamChosenLogFields mirrors dialTCPStreamH2/dialTCPStreamHTTP3 logging fields so
// masque_http_layer_chosen stays aligned with masque_http_layer_attempt (no secrets in message).
func tcpMasqueConnectStreamChosenLogFields(tcpURL *url.URL, options ClientOptions) (target, dial string) {
	target = tcpURL.Host
	if target == "" {
		target = net.JoinHostPort(options.Server, strconv.Itoa(int(options.ServerPort)))
	}
	portNum := int(options.ServerPort)
	if portNum <= 0 {
		portNum = 443
	}
	dial = masqueDialTarget(masqueQuicDialCandidateHost(options), portNum)
	return target, dial
}

func (s *coreSession) dialTCPStream(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	var lastErr error
	for {
		conn, err := s.dialTCPStreamAttempt(ctx, destination)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if !tcpConnectStreamErrMayBenefitFromNextHop(lastErr) {
			s.clearHTTPFallbackConsumedAfterGivingUp()
			return nil, lastErr
		}

		if lastErr != nil && s.tryHTTPFallbackSwitch(lastErr) {
			conn2, err2 := s.dialTCPStreamAttempt(ctx, destination)
			if err2 == nil {
				return conn2, nil
			}
			lastErr = err2
			if !tcpConnectStreamErrMayBenefitFromNextHop(lastErr) {
				s.clearHTTPFallbackConsumedAfterGivingUp()
				return nil, lastErr
			}
		}

		authFail := errors.Is(lastErr, ErrAuthFailed) || ClassifyError(lastErr) == ErrorClassAuth
		churnEligible := s.httpLayerFallback && !authFail && ctx.Err() == nil &&
			!errors.Is(lastErr, context.Canceled) && !errors.Is(lastErr, context.DeadlineExceeded)
		if churnEligible {
			// With http_layer_fallback: mirror ListenPacket's same-hop QUIC/CONNECT rebuild before a second
			// H3↔H2 pivot chance. Omit when fallback is disabled: dialTCPStreamHTTP3 already runs a 3× inner
			// retry budget — repeating a full outer rebuild would double QUIC/H3 CONNECT-stream work on hops.
			s.resetTCPHTTPTransport()
			conn3, err3 := s.dialTCPStreamAttempt(ctx, destination)
			if err3 == nil {
				return conn3, nil
			}
			lastErr = err3
			if !tcpConnectStreamErrMayBenefitFromNextHop(lastErr) {
				s.clearHTTPFallbackConsumedAfterGivingUp()
				return nil, lastErr
			}
			if lastErr != nil && s.tryHTTPFallbackSwitch(lastErr) {
				conn4, err4 := s.dialTCPStreamAttempt(ctx, destination)
				if err4 == nil {
					return conn4, nil
				}
				lastErr = err4
				if !tcpConnectStreamErrMayBenefitFromNextHop(lastErr) {
					s.clearHTTPFallbackConsumedAfterGivingUp()
					return nil, lastErr
				}
			}
		}

		if errors.Is(lastErr, ErrAuthFailed) || ClassifyError(lastErr) == ErrorClassAuth {
			s.clearHTTPFallbackConsumedAfterGivingUp()
			return nil, lastErr
		}

		if ctx.Err() != nil {
			s.clearHTTPFallbackConsumedAfterGivingUp()
			// Another goroutine may cancel after dialTCPStreamAttempt returned a non-cancel
			// error; surface Cause(ctx) so callers see cancellation (parity with dialTCPStreamAttempt).
			return nil, errors.Join(lastErr, context.Cause(ctx))
		}

		if s.dialTCPStreamPreAdvanceHopHook != nil {
			s.dialTCPStreamPreAdvanceHopHook()
		}

		s.mu.Lock()
		if !s.advanceHop() {
			s.mu.Unlock()
			s.clearHTTPFallbackConsumedAfterGivingUp()
			if ctx.Err() != nil {
				return nil, errors.Join(lastErr, context.Cause(ctx))
			}
			return nil, lastErr
		}
		if resetErr := s.resetHopTemplates(); resetErr != nil {
			s.mu.Unlock()
			s.clearHTTPFallbackConsumedAfterGivingUp()
			if ctx.Err() != nil {
				return nil, errors.Join(resetErr, context.Cause(ctx))
			}
			return nil, resetErr
		}
		s.mu.Unlock()
	}
}

// dialTCPStreamAttempt performs one CONNECT-stream dial on the current udpHTTPLayer overlay (H2 extended CONNECT vs H3).
func (s *coreSession) dialTCPStreamAttempt(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	s.mu.Lock()
	httpLayer := s.currentUDPHTTPLayer()
	if s.templateTCP == nil {
		raw := strings.TrimSpace(s.options.TemplateTCP)
		if raw == "" {
			raw = fmt.Sprintf("https://%s:%d/masque/tcp/{target_host}/{target_port}", s.options.Server, s.options.ServerPort)
		}
		t, err := uritemplate.New(raw)
		if err != nil {
			s.mu.Unlock()
			return nil, errors.Join(ErrCapability, E.Cause(err, "invalid TCP MASQUE template"))
		}
		s.templateTCP = t
	}
	templateTCP := s.templateTCP
	options := s.options
	var tcpHTTP *http3.Transport
	if httpLayer != option.MasqueHTTPLayerH2 && s.tcpHTTP == nil {
		tlsMerged := masqueClientTLSConfig(options)
		s.tcpHTTP = &http3.Transport{
			EnableDatagrams:    true,
			DisableCompression: true,
			TLSClientConfig:    tlsMerged,
			Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, _ *quic.Config) (*quic.Conn, error) {
				port := int(s.options.ServerPort)
				if port <= 0 {
					port = 443
				}
				target := masqueDialTarget(masqueQuicDialCandidateHost(s.options), port)
				cfg := applyQUICExperimentalOptions(
					masqueQUICConfigForDial(options),
					options.QUICExperimental,
				)
				return s.quicDialWithPolicy("client_connect_stream")(ctx, target, tlsCfg, cfg)
			},
		}
		applyWarpMasqueHTTP3TransportFields(s.tcpHTTP, options)
	}
	if httpLayer != option.MasqueHTTPLayerH2 {
		tcpHTTP = s.tcpHTTP
	}
	s.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, errors.Join(ErrTCPConnectStreamFailed, context.Cause(ctx))
	default:
	}

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
		return nil, errors.Join(ErrCapability, E.Cause(err, "expand TCP MASQUE template"))
	}
	tcpURL, err := url.Parse(expanded)
	if err != nil {
		return nil, errors.Join(ErrCapability, E.Cause(err, "parse TCP MASQUE URL"))
	}
	if httpLayer == option.MasqueHTTPLayerH2 {
		conn, err := s.dialTCPStreamH2(ctx, tcpURL, options, targetHost, destination)
		if err == nil {
			s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH2)
			logTarget, dialAddr := tcpMasqueConnectStreamChosenLogFields(tcpURL, options)
			log.Printf("masque_http_layer_chosen layer=h2 tag=%s tcp_stream=1 target=%s dial=%s", strings.TrimSpace(options.Tag), logTarget, dialAddr)
			s.resetHTTPFallbackBudgetAfterSuccess()
		}
		return conn, err
	}
	if tcpHTTP == nil {
		return nil, errors.Join(ErrCapability, E.New("internal: masque CONNECT-stream HTTP/3 transport uninitialized"))
	}
	conn, err := s.dialTCPStreamHTTP3(ctx, tcpURL, options, targetHost, targetPort, tcpHTTP)
	if err == nil {
		s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH3)
		logTarget, dialAddr := tcpMasqueConnectStreamChosenLogFields(tcpURL, options)
		log.Printf("masque_http_layer_chosen layer=h3 tag=%s tcp_stream=1 target=%s dial=%s", strings.TrimSpace(options.Tag), logTarget, dialAddr)
		s.resetHTTPFallbackBudgetAfterSuccess()
	}
	return conn, err
}

func (s *coreSession) dialTCPStreamHTTP3(ctx context.Context, tcpURL *url.URL, options ClientOptions, targetHost string, targetPort uint16, tcpHTTP *http3.Transport) (net.Conn, error) {
	serverHost := tcpURL.Host
	if serverHost == "" {
		serverHost = net.JoinHostPort(options.Server, strconv.Itoa(int(options.ServerPort)))
	}
	tcpLogHost := tcpURL.Host
	if tcpLogHost == "" {
		tcpLogHost = serverHost
	}
	portNum := int(options.ServerPort)
	if portNum <= 0 {
		portNum = 443
	}
	dialTCPStreamAddr := masqueDialTarget(masqueQuicDialCandidateHost(options), portNum)
	select {
	case <-ctx.Done():
		return nil, errors.Join(ErrTCPConnectStreamFailed, context.Cause(ctx))
	default:
	}
	log.Printf("masque_http_layer_attempt layer=h3 tag=%s tcp_stream=1 target=%s dial=%s", strings.TrimSpace(options.Tag), tcpLogHost, dialTCPStreamAddr)
	const maxAttempts = 3
	var lastRoundTripErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if ctxErr := context.Cause(ctx); ctxErr != nil {
			return nil, errors.Join(ErrTCPConnectStreamFailed, ctxErr)
		}
		tcpTracef("masque tcp connect_stream request host=%s port=%d attempt=%d", targetHost, targetPort, attempt+1)
		// Unlike H2 Extended CONNECT (`dialTCPStreamH2`), bind the dial ctx to the CONNECT request: quic-go/http3
		// ties stream/teardown to Request.Context, and downstack paths rely on cancel/deadline propagation.
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodConnect, tcpURL.String(), nil)
		if reqErr != nil {
			return nil, errors.Join(ErrTCPConnectStreamFailed, E.Cause(reqErr, "build TCP MASQUE request"))
		}
		req.Host = serverHost
		req.Proto = "HTTP/3"
		req.ProtoMajor = 3
		req.ProtoMinor = 0
		req.Header = make(http.Header)
		if token := warpMasqueConnectStreamBearerToken(options); token != "" {
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
		if ctxErr := context.Cause(ctx); ctxErr != nil {
			_ = pr.Close()
			_ = pw.Close()
			_ = resp.Body.Close()
			return nil, errors.Join(ErrTCPConnectStreamFailed, ctxErr)
		}
		tcpTracef("masque tcp connect_stream success host=%s port=%d status=%d", targetHost, targetPort, resp.StatusCode)
		remoteAddr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort))))
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

func (s *coreSession) getTCPRoundTripper(defaultTransport http.RoundTripper) http.RoundTripper {
	// No s.mu here: CONNECT-IP (openIPSessionLocked) and dialConnectIPTCP hold s.mu across the dial.
	if rt := s.tcpRoundTripper; rt != nil {
		return rt
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
	if s.currentUDPHTTPLayer() == option.MasqueHTTPLayerH2 {
		s.h2UdpMu.Lock()
		if s.h2UdpTransport != nil {
			s.h2UdpTransport.CloseIdleConnections()
			s.h2UdpTransport = nil
		}
		s.h2UdpMu.Unlock()
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tcpHTTP != nil {
		if s.tcpHTTP == s.ipHTTP {
			s.ipHTTP = nil
			s.ipHTTPConn = nil
		}
		s.tcpHTTP.Close()
	}
	tcpTLS := masqueClientTLSConfig(s.options)
	s.tcpHTTP = &http3.Transport{
		EnableDatagrams:    true,
		DisableCompression: true,
		TLSClientConfig:    tcpTLS,
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			port := int(s.options.ServerPort)
			if port <= 0 {
				port = 443
			}
			target := masqueDialTarget(masqueQuicDialCandidateHost(s.options), port)
			cfg := applyQUICExperimentalOptions(
				masqueQUICConfigForDial(s.options),
				s.options.QUICExperimental,
			)
			return s.quicDialWithPolicy("client_connect_stream")(ctx, target, tlsCfg, cfg)
		},
	}
	applyWarpMasqueHTTP3TransportFields(s.tcpHTTP, s.options)
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
	// HTTP/2 + TLS/TCP CONNECT-stream: transient errors do not wrap as QUIC types.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Timeout() {
			return true
		}
		if opErr.Err != nil {
			var errno syscall.Errno
			if errors.As(opErr.Err, &errno) {
				switch errno {
				case syscall.ECONNRESET, syscall.ECONNREFUSED, syscall.ECONNABORTED, syscall.ETIMEDOUT, syscall.EPIPE:
					return true
				}
			}
		}
	}
	var h2cerr http2.ConnectionError
	if errors.As(err, &h2cerr) {
		return true
	}
	es := strings.ToLower(err.Error())
	switch {
	case strings.Contains(es, "broken pipe"),
		strings.Contains(es, "connection reset"),
		strings.Contains(es, "connection aborted"),
		strings.Contains(es, "tls:") && strings.Contains(es, "handshake"):
		return true
	default:
		return false
	}
}

// Kept for test-level compatibility while CONNECT-IP TCP dial path is disabled in runtime.
func isRetryableConnectIPError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
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
	mu            sync.Mutex
	h2PipeWriteMu sync.Mutex // serializes Writes when using H2 Extended CONNECT pipe upload (parity h2ConnectUDPPacketConn.writeMu)
	reader        io.ReadCloser
	writer        io.WriteCloser
	h2UploadPipe  *io.PipeReader // H2 CONNECT-stream upload half; Request body uses h2ExtendedConnectUploadBody noop Close
	h2PipeWriteDL connDeadlines // write deadlines for h2 PipeWriter path (PipeWriter lacks SetWriteDeadline)
	ctx           context.Context
	local         net.Addr
	remote        net.Addr
}

// wrapConnectStreamDataplaneErr tags post-handshake CONNECT-stream faults (H2 Extended CONNECT vs HTTP/3 body)
// so nested library text ("http2:", "handshake", "Extended CONNECT", …) does not drive http_layer_fallback
// or handshake-oriented metrics (parity with CONNECT-UDP / CONNECT-IP dataplane markers).
func (c *streamConn) wrapConnectStreamDataplaneErr(op string, err error) error {
	if err == nil || c == nil {
		return err
	}
	if c.h2UploadPipe != nil {
		return fmt.Errorf("masque h2 dataplane connect-stream %s: %w", op, err)
	}
	return fmt.Errorf("masque h3 dataplane connect-stream %s: %w", op, err)
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
	if errors.Is(err, io.EOF) {
		return n, err
	}
	// H2 Extended CONNECT upload uses io.Pipe; some response-body teardown paths mirror Write's
	// ErrClosedPipe as clean termination (parity TestStreamConnReadKeepsErrClosedPipeWhenDialCtxCanceledH2UploadPipe).
	if c.h2UploadPipe != nil && errors.Is(err, io.ErrClosedPipe) {
		return n, err
	}
	if c.ctx != nil {
		if ctxErr := context.Cause(c.ctx); ctxErr != nil {
			return n, errors.Join(ErrTCPConnectStreamFailed, ctxErr)
		}
	}
	// net.Conn I/O deadlines surface as os.ErrDeadlineExceeded (not identical to context.DeadlineExceeded).
	// Map through ErrTCPConnectStreamFailed so relay-phase tests/classifiers match DeadlineExceeded parity.
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return n, errors.Join(ErrTCPConnectStreamFailed, context.DeadlineExceeded)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return n, errors.Join(ErrTCPConnectStreamFailed, err)
	}
	return n, c.wrapConnectStreamDataplaneErr("read", err)
}
func (c *streamConn) Write(p []byte) (int, error) {
	if c.h2UploadPipe != nil {
		return c.writeH2ExtendedConnectPipe(p)
	}
	n, err := writeAllIOWriter(c.writer, p)
	return c.connectStreamFinishWriteError(n, err)
}

func (c *streamConn) writeH2ExtendedConnectPipe(p []byte) (int, error) {
	c.h2PipeWriteMu.Lock()
	defer c.h2PipeWriteMu.Unlock()
	if len(p) == 0 {
		n, err := writeAllIOWriter(c.writer, p)
		return c.connectStreamFinishWriteError(n, err)
	}
	if c.h2PipeWriteDL.writeTimeoutExceeded() {
		return 0, errors.Join(ErrTCPConnectStreamFailed, context.DeadlineExceeded)
	}
	wNanos := c.h2PipeWriteDL.write.Load()
	var n int
	var err error
	if wNanos == 0 {
		n, err = writeAllIOWriter(c.writer, p)
	} else {
		if time.Now().UnixNano() > wNanos {
			return 0, errors.Join(ErrTCPConnectStreamFailed, context.DeadlineExceeded)
		}
		wctx, wcancel := context.WithDeadline(context.Background(), time.Unix(0, wNanos))
		defer wcancel()
		n, err = c.awaitH2PipeWriterBlockedWriteInterruptible(wctx, p)
	}
	return c.connectStreamFinishWriteError(n, err)
}

// awaitH2PipeWriterBlockedWriteInterruptible mirrors h2ConnectUDPPacketConn.awaitH2UDPReqBodyWrite so a pipe
// upload blocked on flow-control/unread data can observe SetWriteDeadline (Close tears the Pipe).
func (c *streamConn) awaitH2PipeWriterBlockedWriteInterruptible(ctx context.Context, data []byte) (int, error) {
	if c.writer == nil {
		return 0, errors.New("masque h2: connect-stream: nil upload writer")
	}
	ch := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, werr := writeAllIOWriter(c.writer, data)
		ch <- struct {
			n   int
			err error
		}{n, werr}
	}()
	select {
	case <-ctx.Done():
		_ = c.Close()
		got := <-ch
		_ = got
		if ce := context.Cause(ctx); errors.Is(ce, context.Canceled) {
			return 0, ce
		}
		return 0, os.ErrDeadlineExceeded
	case got := <-ch:
		return got.n, got.err
	}
}

func (c *streamConn) connectStreamFinishWriteError(n int, err error) (int, error) {
	if err == nil {
		return n, nil
	}
	if errors.Is(err, io.EOF) {
		return n, err
	}
	// H2 Extended CONNECT upload uses io.Pipe; peer half-close often surfaces as ErrClosedPipe — same
	// «clean termination» as EOF (see connectIPH2CapsulePipeCleanUploadTermination). On H3, ErrClosedPipe
	// during relay may still need Cause(ctx)+ErrTCPConnectStreamFailed (DialContext relay tests).
	if c.h2UploadPipe != nil && errors.Is(err, io.ErrClosedPipe) {
		return n, err
	}
	if c.ctx != nil {
		if ctxErr := context.Cause(c.ctx); ctxErr != nil {
			return n, errors.Join(ErrTCPConnectStreamFailed, ctxErr)
		}
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return n, errors.Join(ErrTCPConnectStreamFailed, context.DeadlineExceeded)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return n, errors.Join(ErrTCPConnectStreamFailed, err)
	}
	return n, c.wrapConnectStreamDataplaneErr("write", err)
}
func (c *streamConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	err1 := c.writer.Close()
	var errMid error
	if c.h2UploadPipe != nil {
		errMid = c.h2UploadPipe.Close()
		c.h2UploadPipe = nil
	}
	err2 := c.reader.Close()
	return errors.Join(err1, errMid, err2)
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
	if c.h2UploadPipe != nil {
		c.h2PipeWriteDL.setWriteDeadline(t)
		return nil
	}
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
		rxSeq := connectIPCounters.packetRxTotal.Add(1)
		connectIPCounters.bytesRxTotal.Add(uint64(n))
		if connectIPCounters.firstRxMarkerEmitted.CompareAndSwap(0, 1) {
			emitConnectIPObservabilityEvent("first_packet_rx")
		}
		maybeEmitConnectIPActiveSnapshot(rxSeq)
	}
	return n, err
}

func (s *connectIPPacketSession) ReadPacketWithContext(ctx context.Context, buffer []byte) (int, error) {
	n, err := s.conn.ReadPacketWithContext(ctx, buffer)
	if err != nil {
		connectIPCounters.packetReadExitTotal.Add(1)
		incConnectIPReadDropReason(classifyConnectIPErrorReason(err))
		emitConnectIPObservabilityEvent("packet_read_exit")
		return n, err
	}
	if n > 0 {
		rxSeq := connectIPCounters.packetRxTotal.Add(1)
		connectIPCounters.bytesRxTotal.Add(uint64(n))
		if connectIPCounters.firstRxMarkerEmitted.CompareAndSwap(0, 1) {
			emitConnectIPObservabilityEvent("first_packet_rx")
		}
		maybeEmitConnectIPActiveSnapshot(rxSeq)
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
	txSeq := connectIPCounters.packetTxTotal.Add(1)
	connectIPCounters.bytesTxTotal.Add(uint64(len(buffer)))
	if connectIPCounters.firstTxMarkerEmitted.CompareAndSwap(0, 1) {
		emitConnectIPObservabilityEvent("first_packet_tx")
	}
	maybeEmitConnectIPActiveSnapshot(txSeq)
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
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
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

// connectIPActiveObsSampleMask=127 → consider ~1 Hz periodic_active only on
// every 128 RX or every 128 TX packets (respectively), using the seq returned
// from packetRxTotal/packetTxTotal Add(1)—no separate sampler atomic.
const connectIPActiveObsSampleMask = uint64(127)

func maybeEmitConnectIPActiveSnapshot(planeTick uint64) {
	last := connectIPCounters.lastActiveEmitUnixMilli.Load()
	if last != 0 {
		if (planeTick & connectIPActiveObsSampleMask) != 0 {
			return
		}
		now := time.Now().UnixMilli()
		if now-last < 1000 {
			return
		}
		if !connectIPCounters.lastActiveEmitUnixMilli.CompareAndSwap(last, now) {
			return
		}
		emitConnectIPObservabilityEvent("periodic_active")
		return
	}
	now := time.Now().UnixMilli()
	if !connectIPCounters.lastActiveEmitUnixMilli.CompareAndSwap(0, now) {
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
	rxSeq := connectIPCounters.packetRxTotal.Add(1)
	connectIPCounters.bytesRxTotal.Add(uint64(rawLen))
	if connectIPCounters.firstRxMarkerEmitted.CompareAndSwap(0, 1) {
		emitConnectIPObservabilityEvent("first_packet_rx")
	}
	maybeEmitConnectIPActiveSnapshot(rxSeq)
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
	txSeq := connectIPCounters.packetTxTotal.Add(1)
	connectIPCounters.bytesTxTotal.Add(uint64(payloadLen))
	if connectIPCounters.firstTxMarkerEmitted.CompareAndSwap(0, 1) {
		emitConnectIPObservabilityEvent("first_packet_tx")
	}
	maybeEmitConnectIPActiveSnapshot(txSeq)
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
	quicConnTier := make(map[string]uint64, len(connectIPCounters.quicTransportTierByPath))
	for k, v := range connectIPCounters.quicTransportTierByPath {
		quicConnTier[k] = v
	}
	quicConnType := make(map[string]string, len(connectIPCounters.quicTransportTypeByPath))
	for k, v := range connectIPCounters.quicTransportTypeByPath {
		quicConnType[k] = v
	}
	bufferTuningOK := connectIPCounters.quicTransportBufferTuningOK
	bufferTuningNOK := connectIPCounters.quicTransportBufferTuningNOK
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
		"quic_transport_packet_conn_tier":             quicConnTier,
		"quic_transport_packet_conn_type":             quicConnType,
		"quic_transport_buffer_tuning_ok":             bufferTuningOK,
		"quic_transport_buffer_tuning_not_ok":         bufferTuningNOK,
		"connect_ip_session_reset_total":              reasons,
		"connect_ip_capsule_unknown_total":            connectip.UnknownCapsuleTotal(),
		"connect_ip_datagram_context_unknown_total":   connectip.UnknownContextDatagramTotal(),
		"connect_ip_datagram_malformed_total":         connectip.MalformedDatagramTotal(),
		"connect_ip_policy_drop_icmp_total":           connectip.PolicyDropICMPTotal(),
		"connect_ip_policy_drop_icmp_attempt_total":   connectip.PolicyDropICMPAttemptTotal(),
		"connect_ip_policy_drop_icmp_reason_total":    policyDropICMPReasonSnapshot(),
		// Process-wide HTTP/3 per-stream DATAGRAM queue drops (patched quic-go http3); correlates with bulk/burst loss.
		"http3_stream_datagram_queue_drop_total":       http3.StreamDatagramQueueDropTotal(),
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

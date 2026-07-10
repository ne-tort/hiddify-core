package session

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	M "github.com/sagernet/sing/common/metadata"
)

// ClientSession is the MASQUE client runtime for CONNECT-stream, CONNECT-IP, and CONNECT-UDP.
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

// ClientFactory constructs a ClientSession from dial options.
type ClientFactory interface {
	NewSession(ctx context.Context, options ClientOptions) (ClientSession, error)
}

// CapabilitySet reports MASQUE extensions available on the current hop overlay.
type CapabilitySet struct {
	ExtendedConnect bool
	Datagrams       bool
	CapsuleProtocol bool
	ConnectUDP      bool
	ConnectIP       bool
	ConnectTCP      bool
}

// ClientOptions configures a MASQUE client session (templates, TLS, hops, WARP fields).
type ClientOptions struct {
	Tag    string
	Server string
	// DialPeer, when non-empty, is the UDP/QUIC packet destination host (often a literal CF edge IP).
	// Masque HTTPS templates and default URIs continue to use Server (typically a hostname).
	DialPeer              string
	ServerPort            uint16
	DataplaneMode             string
	TemplateUDP               string
	TemplateIP            string
	ConnectIPScopeTarget  string
	ConnectIPScopeIPProto uint8
	TemplateTCP           string
	FallbackPolicy        string
	TCPMode               string
	ServerToken           string
	// ClientBasicUsername / ClientBasicPassword: optional RFC 7617 Basic for CONNECT-stream / CONNECT-IP / H2 CONNECT-UDP.
	ClientBasicUsername string
	ClientBasicPassword string
	// MasqueQUICCryptoTLS is stdlib TLS for QUIC/HTTP3 (required unless WarpMasqueClientCert is set).
	MasqueQUICCryptoTLS *tls.Config
	// MasqueTCPDialTLS performs client TLS over TCP for HTTP/2 overlay (stdlib or uTLS via sing-box).
	MasqueTCPDialTLS         func(ctx context.Context, raw net.Conn, nextProtos []string, serverAddr string) (net.Conn, error)
	QUICExperimental         QUICExperimentalOptions
	ConnectIPDatagramCeiling uint32
	Hops                     []HopOptions
	QUICDial                 QUICDialFunc
	TCPDial                  MasqueTCPDialFunc
	MasqueEffectiveHTTPLayer string
	HTTPLayerAuto            bool
	HTTPLayerSuccess         func(layer string, id HTTPLayerCacheDialIdentity)
	// WarpMasque fields: Cloudflare consumer MASQUE / usque dataplane parity (optional for generic masque).
	WarpMasqueClientCert        tls.Certificate
	WarpMasquePinnedPubKey      *ecdsa.PublicKey
	WarpMasqueLegacyH3Extras    bool
	WarpConnectIPProtocol       string
	WarpMasqueDeviceBearerToken string
	ProfileLocalIPv4            string
	ProfileLocalIPv6            string
	// TCPIPv6PathBracket mirrors option.MasqueEndpointOptions.tcp_ipv6_path_bracket (CONNECT-stream path only).
	TCPIPv6PathBracket bool
	// ConnectStreamMode mirrors option.MasqueEndpointOptions.connect_stream_mode (single_bidi | thin_bidi | split_legs).
	ConnectStreamMode string
}

// QUICExperimentalOptions tunes QUIC transport knobs for lab / WARP profiles.
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

// QUICDialFunc dials a QUIC connection for HTTP/3 MASQUE overlays.
type QUICDialFunc func(ctx context.Context, address string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error)

// MasqueTCPDialFunc wires outbound TCP (+TLS handshake target) for the HTTP/2 MASQUE overlay.
type MasqueTCPDialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// HopOptions is one hop in a multi-hop MASQUE chain.
type HopOptions struct {
	Tag    string
	Via    string
	Server string
	Port   uint16
}

// IPPacketSession is the CONNECT-IP packet plane (RFC 9484).
type IPPacketSession interface {
	ReadPacket(buffer []byte) (int, error)
	WritePacket(buffer []byte) (icmp []byte, err error)
	Close() error
}

// IPPacketSessionWithContext is an optional context-aware packet reader for the CONNECT-IP plane.
type IPPacketSessionWithContext interface {
	ReadPacketWithContext(ctx context.Context, buffer []byte) (int, error)
}

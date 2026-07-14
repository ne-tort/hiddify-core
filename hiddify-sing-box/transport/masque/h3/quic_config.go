package h3

import (
	"crypto/tls"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICDialProfile carries the WARP/overlay fields that influence HTTP/3 QUIC tuning.
// Defined in h3 (not session) to avoid h3 ↔ session import cycles.
type QUICDialProfile struct {
	WarpMasqueClientCert     tls.Certificate
	WarpMasqueLegacyH3Extras bool
	WarpConnectIPProtocol    string
	// CongestionControl: empty → bbr (prod). Also cubic, new_reno, bbr2, bbr2_aggressive.
	// Applied via quic.Config and post-dial ApplyExternalCongestionControl for meta2 BBR.
	CongestionControl string
}

func (p QUICDialProfile) hasWarpClientCert() bool {
	return len(p.WarpMasqueClientCert.Certificate) > 0
}

// DefaultUDPInitialPacketSize is the first-flight QUIC packet size for self-hosted CONNECT-UDP/IP
// and CONNECT-stream (1420 B leaves room for CONNECT-IP datagram framing on bulk paths).
const DefaultUDPInitialPacketSize uint16 = 1420

// packetPlaneInitialPacketSize is the first-flight QUIC packet size for CONNECT-IP/UDP.
func packetPlaneInitialPacketSize() uint16 {
	return DefaultUDPInitialPacketSize
}

const (
	// BulkStreamFCFloorBytes is the minimum CONNECT-stream QUIC stream FC that escapes the
	// bench-shaped 64 KiB/RTT ceiling (S43 L256 → >21 Mbit/s @ 35 ms). Prod configs use 128 MiB.
	BulkStreamFCFloorBytes = 256 * 1024

	// ConnectStreamMaxIncomingStreams is the peer bidi budget on the MASQUE HTTP/3 listener.
	// Stock quic-go DefaultMaxIncomingStreams=100 deadlocks OpenStreamSync under concurrent
	// browser/speedtest flows on a shared QUIC (dial hangs → connect roundtrip context canceled @60s).
	ConnectStreamMaxIncomingStreams int64 = 4096

	defaultInitialStreamRecvWindow     = 16 << 20  // 16 MiB
	defaultMaxStreamRecvWindow         = 96 << 20  // 96 MiB
	defaultInitialConnectionRecvWindow = 24 << 20  // ≥ 1.5 × stream initial
	defaultMaxConnectionRecvWindow     = 128 << 20 // 128 MiB
)

// PacketPlaneQUICConfig applies defaults for CONNECT-IP / CONNECT-UDP over HTTP/3.
func PacketPlaneQUICConfig(base *quic.Config) *quic.Config {
	if base == nil {
		base = &quic.Config{}
	} else {
		base = base.Clone()
	}
	if base.MaxIdleTimeout == 0 {
		base.MaxIdleTimeout = 24 * time.Hour
	}
	if base.HandshakeIdleTimeout == 0 {
		base.HandshakeIdleTimeout = packetPlaneHandshakeIdleTimeout()
	}
	if base.KeepAlivePeriod == 0 {
		base.KeepAlivePeriod = packetPlaneKeepAlivePeriod()
	}
	if base.InitialStreamReceiveWindow == 0 {
		base.InitialStreamReceiveWindow = defaultInitialStreamRecvWindow
	}
	if base.MaxStreamReceiveWindow == 0 {
		base.MaxStreamReceiveWindow = defaultMaxStreamRecvWindow
	}
	if base.InitialConnectionReceiveWindow == 0 {
		base.InitialConnectionReceiveWindow = defaultInitialConnectionRecvWindow
	}
	if base.MaxConnectionReceiveWindow == 0 {
		base.MaxConnectionReceiveWindow = defaultMaxConnectionRecvWindow
	}
	return base
}

func boostTCPBulkStreamQUICReceiveWindows(cfg *quic.Config) {
	if cfg == nil {
		return
	}
	const streamMax = 128 << 20
	const connMax = 192 << 20
	if cfg.MaxStreamReceiveWindow < streamMax {
		cfg.MaxStreamReceiveWindow = streamMax
	}
	if cfg.InitialStreamReceiveWindow < streamMax {
		cfg.InitialStreamReceiveWindow = streamMax
	}
	if cfg.MaxConnectionReceiveWindow < connMax {
		cfg.MaxConnectionReceiveWindow = connMax
	}
	if cfg.InitialConnectionReceiveWindow < connMax {
		cfg.InitialConnectionReceiveWindow = connMax
	}
}

// EnforceConnectStreamBulkFCFloor raises QUIC receive windows to at least BulkStreamFCFloorBytes.
func EnforceConnectStreamBulkFCFloor(cfg *quic.Config) {
	if cfg == nil {
		return
	}
	if cfg.InitialStreamReceiveWindow < BulkStreamFCFloorBytes {
		cfg.InitialStreamReceiveWindow = BulkStreamFCFloorBytes
	}
	if cfg.MaxStreamReceiveWindow < BulkStreamFCFloorBytes {
		cfg.MaxStreamReceiveWindow = BulkStreamFCFloorBytes
	}
	const connFloor = BulkStreamFCFloorBytes * 2
	if cfg.InitialConnectionReceiveWindow < connFloor {
		cfg.InitialConnectionReceiveWindow = connFloor
	}
	if cfg.MaxConnectionReceiveWindow < connFloor {
		cfg.MaxConnectionReceiveWindow = connFloor
	}
}

// EnforceConnectStreamPeerBidiBudget raises MaxIncomingStreams so peer OpenStreamSync cannot stall
// at stock 100 under concurrent CONNECT-stream VPN traffic. MaxIncomingStreams < 0 means "disabled"
// (HTTP/3 client refuses peer-initiated bidi) and is left alone.
func EnforceConnectStreamPeerBidiBudget(cfg *quic.Config) {
	if cfg == nil {
		return
	}
	if cfg.MaxIncomingStreams < 0 {
		return
	}
	if cfg.MaxIncomingStreams < ConnectStreamMaxIncomingStreams {
		cfg.MaxIncomingStreams = ConnectStreamMaxIncomingStreams
	}
}

// FinalizeConnectStreamQUICConfig applies P8 bulk FC floor, prod window boost, and peer stream budget.
func FinalizeConnectStreamQUICConfig(cfg *quic.Config) {
	if cfg == nil {
		return
	}
	EnforceConnectStreamBulkFCFloor(cfg)
	boostTCPBulkStreamQUICReceiveWindows(cfg)
	EnforceConnectStreamPeerBidiBudget(cfg)
}

func applyCongestionControl(cfg *quic.Config, name string) {
	if cfg == nil {
		return
	}
	switch name {
	case "", quic.CongestionControlBBR:
		// Default prod: post-dial ApplyCongestionControl installs meta2 BBR.
		cfg.CongestionControl = quic.CongestionControlBBR
	case quic.CongestionControlNewReno:
		cfg.CongestionControl = quic.CongestionControlNewReno
	case quic.CongestionControlCubic:
		cfg.CongestionControl = quic.CongestionControlCubic
	case quic.CongestionControlBBR2:
		cfg.CongestionControl = quic.CongestionControlBBR2
	case quic.CongestionControlBBR2Aggressive:
		cfg.CongestionControl = quic.CongestionControlBBR2Aggressive
	default:
		cfg.CongestionControl = quic.CongestionControlBBR
	}
}

// NewPacketPlaneQUICConfig returns CONNECT-UDP/IP defaults with datagrams enabled.
func NewPacketPlaneQUICConfig() *quic.Config {
	return PacketPlaneQUICConfig(&quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: packetPlaneInitialPacketSize(),
	})
}

// WarpCloudflareQUICBase returns QUIC defaults aligned with usque / Cloudflare WARP edges.
func WarpCloudflareQUICBase() *quic.Config {
	return &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 30 * time.Second,
	}
}

// QUICConfigForDial builds the shared CONNECT-IP/UDP QUIC config for a client session.
func QUICConfigForDial(profile QUICDialProfile) *quic.Config {
	var cfg *quic.Config
	if profile.hasWarpClientCert() {
		cfg = PacketPlaneQUICConfig(WarpCloudflareQUICBase())
	} else {
		cfg = NewPacketPlaneQUICConfig()
	}
	FinalizeConnectStreamQUICConfig(cfg)
	applyCongestionControl(cfg, profile.CongestionControl)
	return cfg
}

// TCPConnectStreamQUICConfig is used for the dedicated http3.Transport behind CONNECT-stream.
func TCPConnectStreamQUICConfig(profile QUICDialProfile) *quic.Config {
	var cfg *quic.Config
	if profile.hasWarpClientCert() {
		cfg = PacketPlaneQUICConfig(WarpCloudflareQUICBase())
	} else {
		cfg = PacketPlaneQUICConfig(&quic.Config{
			EnableDatagrams:   TCPConnectStreamHTTP3EnableDatagrams(profile),
			InitialPacketSize: packetPlaneInitialPacketSize(),
		})
	}
	FinalizeConnectStreamQUICConfig(cfg)
	// HTTP/3 client must not advertise peer bidi budget; server MaxIncomingStreams limits dials.
	cfg.MaxIncomingStreams = -1
	applyCongestionControl(cfg, profile.CongestionControl)
	return cfg
}

// TCPConnectStreamHTTP3EnableDatagrams controls http3.Transport.EnableDatagrams for CONNECT-stream.
func TCPConnectStreamHTTP3EnableDatagrams(profile QUICDialProfile) bool {
	if profile.hasWarpClientCert() {
		return true
	}
	if profile.WarpMasqueLegacyH3Extras {
		return true
	}
	if CfConnectIPProtocol(profile.WarpConnectIPProtocol) {
		return true
	}
	return false
}

// packetPlaneKeepAlivePeriod tunes QUIC PING cadence for field NAT paths.
func packetPlaneKeepAlivePeriod() time.Duration {
	return 15 * time.Second
}

// packetPlaneHandshakeIdleTimeout tunes pre-handshake idle budget.
func packetPlaneHandshakeIdleTimeout() time.Duration {
	return 15 * time.Second
}

// HTTPServerQUICConfig returns QUIC settings for the MASQUE HTTP/3 server listener.
// congestionControl: empty → bbr (prod). Also cubic, new_reno, bbr2, bbr2_aggressive.
func HTTPServerQUICConfig(congestionControl ...string) *quic.Config {
	cc := ""
	if len(congestionControl) > 0 {
		cc = congestionControl[0]
	}
	cfg := PacketPlaneQUICConfig(&quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: packetPlaneInitialPacketSize(),
	})
	FinalizeConnectStreamQUICConfig(cfg)
	applyCongestionControl(cfg, cc)
	return cfg
}

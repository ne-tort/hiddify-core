package h3

import (
	"crypto/tls"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICDialProfile carries the WARP/overlay fields that influence HTTP/3 QUIC tuning.
// Defined in h3 (not session) to avoid h3 ↔ session import cycles.
type QUICDialProfile struct {
	WarpMasqueClientCert     tls.Certificate
	WarpMasqueLegacyH3Extras bool
	WarpConnectIPProtocol    string
}

func (p QUICDialProfile) hasWarpClientCert() bool {
	return len(p.WarpMasqueClientCert.Certificate) > 0
}

// DefaultUDPInitialPacketSize is the first-flight QUIC packet size for self-hosted CONNECT-UDP/IP
// and CONNECT-stream (1420 B leaves room for CONNECT-IP datagram framing on bulk paths).
const DefaultUDPInitialPacketSize uint16 = 1420

// packetPlaneInitialPacketSize aligns QUIC first-flight MTU with HIDDIFY_MASQUE_DATAGRAM_CEILING_MAX
// so CONNECT-IP can carry larger IPv4 segments per DATAGRAM on jumbo-capable paths (Docker bridge, loopback).
func packetPlaneInitialPacketSize() uint16 {
	raw := strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_DATAGRAM_CEILING_MAX"))
	if raw == "" {
		return DefaultUDPInitialPacketSize
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1280 {
		return DefaultUDPInitialPacketSize
	}
	// ceiling + RFC9297/H3 datagram prefix headroom; cap below common jumbo.
	want := n + 96
	if want > 9000 {
		want = 9000
	}
	if want < int(DefaultUDPInitialPacketSize) {
		return DefaultUDPInitialPacketSize
	}
	return uint16(want)
}

const (
	// BulkStreamFCFloorBytes is the minimum CONNECT-stream QUIC stream FC that escapes the
	// bench-shaped 64 KiB/RTT ceiling (S43 L256 → >21 Mbit/s @ 35 ms). Prod configs use 128 MiB.
	BulkStreamFCFloorBytes = 256 * 1024

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
// Called after quic_experimental merge so lab knobs cannot reintroduce the 64 KiB/RTT ceiling.
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

// FinalizeConnectStreamQUICConfig applies P8 bulk FC floor then prod window boost after experimental merge.
func FinalizeConnectStreamQUICConfig(cfg *quic.Config) {
	EnforceConnectStreamBulkFCFloor(cfg)
	boostTCPBulkStreamQUICReceiveWindows(cfg)
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
	return cfg
}

// TCPConnectStreamHTTP3EnableDatagrams controls http3.Transport.EnableDatagrams for CONNECT-stream.
// Labs can restore the historic default via HIDDIFY_MASQUE_TCP_HTTP3_LEGACY_DATAGRAMS=1.
func TCPConnectStreamHTTP3EnableDatagrams(profile QUICDialProfile) bool {
	if tcpStreamHTTP3LegacyDatagramsEnv() {
		return true
	}
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

// packetPlaneKeepAlivePeriod tunes QUIC PING cadence (MASQUE_QUIC_KEEPALIVE_MS).
// Shorter keepalive helps Docker/NAT field paths where 15s idle gaps drop UDP mappings.
func packetPlaneKeepAlivePeriod() time.Duration {
	const defaultPeriod = 15 * time.Second
	raw := strings.TrimSpace(os.Getenv("MASQUE_QUIC_KEEPALIVE_MS"))
	if raw == "" {
		return defaultPeriod
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms <= 0 {
		return defaultPeriod
	}
	return time.Duration(ms) * time.Millisecond
}

// packetPlaneHandshakeIdleTimeout tunes pre-handshake idle budget (MASQUE_QUIC_HANDSHAKE_IDLE_MS).
// Field remote paths with higher RTT may need >5s (stock quic-go default).
func packetPlaneHandshakeIdleTimeout() time.Duration {
	// Field remote paths with higher RTT need >5s (REF1-2); default matches bench tuning.
	const defaultPeriod = 15 * time.Second
	raw := strings.TrimSpace(os.Getenv("MASQUE_QUIC_HANDSHAKE_IDLE_MS"))
	if raw == "" {
		return defaultPeriod
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms <= 0 {
		return defaultPeriod
	}
	return time.Duration(ms) * time.Millisecond
}

func tcpStreamHTTP3LegacyDatagramsEnv() bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv("HIDDIFY_MASQUE_TCP_HTTP3_LEGACY_DATAGRAMS")))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// HTTPServerQUICConfig returns QUIC settings for the MASQUE HTTP/3 server listener.
func HTTPServerQUICConfig() *quic.Config {
	cfg := PacketPlaneQUICConfig(&quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: packetPlaneInitialPacketSize(),
	})
	FinalizeConnectStreamQUICConfig(cfg)
	return cfg
}

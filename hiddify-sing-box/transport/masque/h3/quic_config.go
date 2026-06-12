package h3

import (
	"crypto/tls"
	"os"
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

const (
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
	if base.KeepAlivePeriod == 0 {
		base.KeepAlivePeriod = 15 * time.Second
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

// NewPacketPlaneQUICConfig returns CONNECT-UDP/IP defaults with datagrams enabled.
func NewPacketPlaneQUICConfig() *quic.Config {
	return PacketPlaneQUICConfig(&quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: DefaultUDPInitialPacketSize,
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
	boostTCPBulkStreamQUICReceiveWindows(cfg)
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
			InitialPacketSize: DefaultUDPInitialPacketSize,
		})
	}
	boostTCPBulkStreamQUICReceiveWindows(cfg)
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
		InitialPacketSize: DefaultUDPInitialPacketSize,
	})
	boostTCPBulkStreamQUICReceiveWindows(cfg)
	return cfg
}

package h3

import (
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	qcong "github.com/quic-go/quic-go/congestion"
	bbr2 "github.com/sagernet/sing-box/transport/masque/congestion_bbr2"
	meta2 "github.com/sagernet/sing-box/transport/masque/congestion_meta2"
)

// Initial BBR (meta2) cwnd in packets — matches sing-quic/congestion_meta1.InitialCongestionWindow (HY2).
const bbrInitialCongestionWindowPackets = 32

// ApplyCongestionControl installs the send CC after dial/accept (HY2/TUIC pattern).
//
// new_reno / cubic stay on CubicSender created at conn start (quic.Config.CongestionControl,
// preserved through populateConfig). Advanced algos replace that sender via SetCongestionControl:
//
//	bbr              → congestion_meta2 (HY2 default)
//	bbr2             → congestion_bbr2 default params
//	bbr2_aggressive  → congestion_bbr2 aggressive params
//
// Empty name is treated as the endpoint default (bbr).
func ApplyCongestionControl(conn *quic.Conn, name string) {
	if conn == nil {
		return
	}
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		n = quic.CongestionControlBBR
	}
	switch n {
	case quic.CongestionControlNewReno, quic.CongestionControlCubic:
		// CubicSender already configured from quic.Config at handshake start.
		return
	case quic.CongestionControlBBR:
		packetSize := datagramSize(conn)
		conn.SetCongestionControl(meta2.NewBbrSender(
			meta2.DefaultClock{TimeFunc: time.Now},
			packetSize,
			qcong.ByteCount(bbrInitialCongestionWindowPackets),
		))
	case quic.CongestionControlBBR2:
		packetSize := datagramSize(conn)
		// IW=32 like meta2/HY2 — stock quiche IW=10 traps WAN pacing ~3 Mbit/s.
		conn.SetCongestionControl(bbr2.NewBBR2Sender(
			bbr2.DefaultClock{TimeFunc: time.Now},
			packetSize,
			qcong.ByteCount(bbrInitialCongestionWindowPackets)*packetSize,
			false,
		))
	case quic.CongestionControlBBR2Aggressive:
		packetSize := datagramSize(conn)
		conn.SetCongestionControl(bbr2.NewBBR2Sender(
			bbr2.DefaultClock{TimeFunc: time.Now},
			packetSize,
			qcong.ByteCount(bbrInitialCongestionWindowPackets)*packetSize,
			true,
		))
	}
}

// ApplyExternalCongestionControl is the historical name; prefer ApplyCongestionControl.
func ApplyExternalCongestionControl(conn *quic.Conn, name string) {
	ApplyCongestionControl(conn, name)
}

func datagramSize(conn *quic.Conn) qcong.ByteCount {
	packetSize := qcong.ByteCount(DefaultUDPInitialPacketSize)
	if cfg := conn.Config(); cfg != nil && cfg.InitialPacketSize > 0 {
		packetSize = qcong.ByteCount(cfg.InitialPacketSize)
	}
	if packetSize <= 0 {
		packetSize = qcong.InitialPacketSize
	}
	return packetSize
}

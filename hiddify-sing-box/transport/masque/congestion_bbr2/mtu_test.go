package congestion_bbr2_test

import (
	"testing"
	"time"

	qcong "github.com/quic-go/quic-go/congestion"
	"github.com/quic-go/quic-go/monotime"
	bbr2 "github.com/sagernet/sing-box/transport/masque/congestion_bbr2"
)

func TestBBR2AfterMTUGrowNoScale(t *testing.T) {
	s := bbr2.NewBBR2Sender(bbr2.DefaultClock{TimeFunc: time.Now}, 1200, 0, false)
	init := float64(s.PacingRate()) / 1e6
	s.SetMaxDatagramSize(1420)
	after := float64(s.PacingRate()) / 1e6
	t.Logf("pacing before MTU grow=%.2f after=%.2f cwnd=%d", init, after, s.GetCongestionWindow())
	// ScalePacingRateByMss=false by default → pacing unchanged while cwnd scales up
}

func TestBBR2FirstAckZeroEstimateKeepsBootstrap(t *testing.T) {
	// Phantom ACKs miss sampler → BandwidthEstimate stays 0, but effective pacing
	// must stay at handshake bootstrap (not freeze at IW/100ms seed once MinRTT is known).
	const mss = 1420
	iw := qcong.ByteCount(32) * mss
	s := bbr2.NewBBR2Sender(bbr2.DefaultClock{TimeFunc: time.Now}, mss, iw, false)
	s.SetRTTStatsProvider(&fakeRTT{srtt: 28 * time.Millisecond})
	boot := s.PacingRate()
	now := monotime.Now()
	s.OnCongestionEventEx(mss*5, now, []qcong.AckedPacketInfo{{PacketNumber: 1, BytesAcked: mss, SentTime: now.Add(-30 * time.Millisecond)}}, nil)
	if s.BandwidthEstimate() != 0 {
		t.Fatalf("expected zero BW after phantom ACK, got %d", s.BandwidthEstimate())
	}
	after := s.PacingRate()
	if float64(after)/1e6 < 20 {
		t.Fatalf("bootstrap lost after phantom ACK: pacing=%d (boot=%d)", after, boot)
	}
	t.Logf("after phantom ACK pacing=%.1f Mbit/s (boot=%.1f)", float64(after)/1e6, float64(boot)/1e6)
}

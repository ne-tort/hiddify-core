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

func TestBBR2FirstAckZeroEstimateEarlyReturn(t *testing.T) {
	// Document: updatePacingRate returns early when BandwidthEstimate==0;
	// phantom ACKs that don't hit sampler leave pacing at initial forever until a valid sample.
	const mss = 1420
	s := bbr2.NewBBR2Sender(bbr2.DefaultClock{TimeFunc: time.Now}, mss, 0, false)
	init := s.PacingRate()
	now := monotime.Now()
	// only phantom
	s.OnCongestionEventEx(mss*5, now, []qcong.AckedPacketInfo{{PacketNumber: 1, BytesAcked: mss, SentTime: now.Add(-30 * time.Millisecond)}}, nil)
	if s.PacingRate() != init || s.BandwidthEstimate() != 0 {
		t.Fatalf("expected stuck at init after phantom; pacing=%d bw=%d", s.PacingRate(), s.BandwidthEstimate())
	}
	t.Logf("documented stuck-at-initial after samples miss: %.2f Mbit/s", float64(init)/1e6)
}

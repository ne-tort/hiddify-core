package congestion_bbr2_test

import (
	"testing"
	"time"

	qcong "github.com/quic-go/quic-go/congestion"
	"github.com/quic-go/quic-go/monotime"
	bbr2 "github.com/sagernet/sing-box/transport/masque/congestion_bbr2"
)

// Prod apply uses IW=32×MSS; handshake MinRTT~28ms must not leave pacing at ~3 Mbit/s.
func TestBBR2BootstrapPacingWithHandshakeRTT(t *testing.T) {
	const mss = 1420
	iw := qcong.ByteCount(32) * mss
	s := bbr2.NewBBR2Sender(bbr2.DefaultClock{TimeFunc: time.Now}, mss, iw, false)

	before := float64(s.PacingRate()) / 1e6
	s.SetRTTStatsProvider(&fakeRTT{srtt: 28 * time.Millisecond})
	after := float64(s.PacingRate()) / 1e6
	t.Logf("pacing before_rtt=%.1f after_rtt=%.1f Mbit/s cwnd=%d", before, after, s.GetCongestionWindow())

	// IW=32×1420 / 28ms × 2.885 ≈ 37.7 Mbit/s — must clear the old ~3 Mbit cage.
	if after < 20 {
		t.Fatalf("bootstrap pacing too low after MinRTT=28ms: %.1f Mbit/s", after)
	}
}

func TestBBR2PhantomLossDoesNotPinBandwidthLo(t *testing.T) {
	const mss = 1420
	iw := qcong.ByteCount(32) * mss
	s := bbr2.NewBBR2Sender(bbr2.DefaultClock{TimeFunc: time.Now}, mss, iw, false)
	s.SetRTTStatsProvider(&fakeRTT{srtt: 28 * time.Millisecond})
	now := monotime.Now()

	// Losses for packets never OnPacketSent (SetCongestionControl mid-flight).
	lost := []qcong.LostPacketInfo{
		{PacketNumber: 1, BytesLost: mss},
		{PacketNumber: 2, BytesLost: mss},
	}
	s.OnCongestionEventEx(0, now, nil, lost)
	if s.BandwidthEstimate() != 0 {
		t.Fatalf("expected zero BW after phantom loss only, got %d", s.BandwidthEstimate())
	}

	var pn qcong.PacketNumber = 100
	inFlight := qcong.ByteCount(0)
	var sent []qcong.PacketNumber
	for i := 0; i < 16; i++ {
		pn++
		s.OnPacketSent(now, inFlight, pn, mss, true)
		inFlight += mss
		sent = append(sent, pn)
	}
	ackT := now.Add(28 * time.Millisecond)
	acked := make([]qcong.AckedPacketInfo, 0, len(sent))
	for i, p := range sent {
		acked = append(acked, qcong.AckedPacketInfo{
			PacketNumber: p,
			BytesAcked:   mss,
			SentTime:     now.Add(time.Duration(i) * time.Millisecond),
		})
	}
	s.OnCongestionEventEx(inFlight, ackT, acked, nil)
	bw := float64(s.BandwidthEstimate()) / 1e6
	pacing := float64(s.PacingRate()) / 1e6
	t.Logf("after_real_acks pacing=%.1f bw=%.1f cwnd=%d", pacing, bw, s.GetCongestionWindow())
	if pacing < 10 {
		t.Fatalf("phantom losses pinned pacing: %.1f Mbit/s", pacing)
	}
}

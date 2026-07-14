package congestion_bbr2_test

import (
	"testing"
	"time"

	qcong "github.com/quic-go/quic-go/congestion"
	"github.com/quic-go/quic-go/monotime"
	bbr2 "github.com/sagernet/sing-box/transport/masque/congestion_bbr2"
)

// Simulates SetCongestionControl after some Cubic traffic: first ACKs may reference
// packet numbers that were never OnPacketSent into BBR2's sampler.
func TestBBR2StuckWhenEarlyAcksMissSampler(t *testing.T) {
	const mss = 1420
	iw := qcong.ByteCount(32) * mss
	s := bbr2.NewBBR2Sender(bbr2.DefaultClock{TimeFunc: time.Now}, mss, iw, false)
	s.SetRTTStatsProvider(&fakeRTT{srtt: 28 * time.Millisecond})
	initM := float64(s.PacingRate()) / 1e6
	now := monotime.Now()

	// ACK phantom (pre-swap) packets only — not in sampler
	acked := []qcong.AckedPacketInfo{{PacketNumber: 5, BytesAcked: mss, SentTime: now.Add(-30 * time.Millisecond)}}
	s.OnCongestionEventEx(mss, now, acked, nil)
	afterPhantom := float64(s.PacingRate()) / 1e6
	t.Logf("after_phantom_acks pacing=%.2f (init=%.2f) bw=%d", afterPhantom, initM, uint64(s.BandwidthEstimate()))

	// Now real sends + acks
	var pn qcong.PacketNumber = 100
	for round := 0; round < 10; round++ {
		inFlight := qcong.ByteCount(0)
		var sent []qcong.PacketNumber
		sendT := now.Add(time.Duration(round) * 40 * time.Millisecond)
		for i := 0; i < 10; i++ {
			pn++
			s.OnPacketSent(sendT.Add(time.Duration(i)*time.Millisecond), inFlight, pn, mss, true)
			inFlight += mss
			sent = append(sent, pn)
		}
		ackT := sendT.Add(30 * time.Millisecond)
		var ak []qcong.AckedPacketInfo
		for i, p := range sent {
			ak = append(ak, qcong.AckedPacketInfo{PacketNumber: p, BytesAcked: mss, SentTime: sendT.Add(time.Duration(i) * time.Millisecond)})
		}
		s.OnCongestionEventEx(inFlight, ackT, ak, nil)
	}
	final := float64(s.PacingRate()) / 1e6
	t.Logf("after_real_traffic pacing=%.2f Mbit/s bw=%d cwnd=%d", final, uint64(s.BandwidthEstimate()), s.GetCongestionWindow())
	if final < 10 {
		t.Fatalf("stuck after real traffic: %.2f (bootstrap was %.2f)", final, initM)
	}
}

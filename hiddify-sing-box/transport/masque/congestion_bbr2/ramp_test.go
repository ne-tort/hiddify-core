package congestion_bbr2_test

import (
	"testing"
	"time"

	qcong "github.com/quic-go/quic-go/congestion"
	"github.com/quic-go/quic-go/monotime"
	bbr2 "github.com/sagernet/sing-box/transport/masque/congestion_bbr2"
)

func TestBBR2PacingRampsWithSyntheticAcks(t *testing.T) {
	const mss = 1420
	s := bbr2.NewBBR2Sender(bbr2.DefaultClock{TimeFunc: time.Now}, mss, 0, false)
	s.SetRTTStatsProvider(&fakeRTT{srtt: 28 * time.Millisecond})

	initRate := s.PacingRate()
	t.Logf("initial_pacing_bps=%d (~%.1f Mbit/s) cwnd=%d", uint64(initRate), float64(initRate)/1e6, s.GetCongestionWindow())

	now := monotime.Now()
	var pn qcong.PacketNumber
	// send 20 packets then ack them after 28ms, repeatedly for several rounds
	for round := 0; round < 30; round++ {
		sent := make([]qcong.PacketNumber, 0, 20)
		inFlight := qcong.ByteCount(0)
		for i := 0; i < 20; i++ {
			pn++
			s.OnPacketSent(now, inFlight, pn, mss, true)
			inFlight += mss
			sent = append(sent, pn)
		}
		ackTime := now.Add(28 * time.Millisecond)
		acked := make([]qcong.AckedPacketInfo, 0, len(sent))
		for i, p := range sent {
			acked = append(acked, qcong.AckedPacketInfo{
				PacketNumber: p,
				BytesAcked:   mss,
				SentTime:     now,
			})
			_ = i
		}
		s.OnCongestionEventEx(inFlight, ackTime, acked, nil)
		s.OnPacketsLost(sent[0])
		now = ackTime.Add(time.Millisecond)
		if round%5 == 4 {
			t.Logf("round=%d pacing_bps=%d (~%.1f Mbit/s) cwnd=%d mode=%v bw=%d",
				round, uint64(s.PacingRate()), float64(s.PacingRate())/1e6, s.GetCongestionWindow(), s.Mode(), uint64(s.BandwidthEstimate()))
		}
	}
	final := float64(s.PacingRate()) / 1e6
	if final < 10 {
		t.Fatalf("pacing did not ramp: final=%.1f Mbit/s (stuck near initial ~3?)", final)
	}
}

type fakeRTT struct{ srtt time.Duration }

func (f *fakeRTT) MinRTT() time.Duration                 { return f.srtt }
func (f *fakeRTT) LatestRTT() time.Duration              { return f.srtt }
func (f *fakeRTT) SmoothedRTT() time.Duration            { return f.srtt }
func (f *fakeRTT) MeanDeviation() time.Duration          { return f.srtt / 4 }
func (f *fakeRTT) MaxAckDelay() time.Duration            { return 25 * time.Millisecond }
func (f *fakeRTT) PTO(bool) time.Duration                { return f.srtt * 2 }
func (f *fakeRTT) UpdateRTT(sendDelta, ackDelay time.Duration) {}
func (f *fakeRTT) SetMaxAckDelay(time.Duration)          {}
func (f *fakeRTT) SetInitialRTT(time.Duration)           {}

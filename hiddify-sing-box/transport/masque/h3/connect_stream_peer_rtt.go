package h3

import (
	"time"

	"github.com/quic-go/quic-go"
	sched "github.com/sagernet/sing-box/transport/masque/stream/sched"
)

var (
	testConnectStreamPeerRTT    time.Duration
	testConnectStreamPeerRTTSet bool
)

// SetTestConnectStreamPeerRTT overrides peer RTT for synth gates (tests only).
func SetTestConnectStreamPeerRTT(rtt time.Duration) {
	testConnectStreamPeerRTT = rtt
	testConnectStreamPeerRTTSet = true
}

// ClearTestConnectStreamPeerRTT clears the test-only RTT override.
func ClearTestConnectStreamPeerRTT() {
	testConnectStreamPeerRTT = 0
	testConnectStreamPeerRTTSet = false
}

func peerConnectStreamRTT(c *TunnelConn) time.Duration {
	if testConnectStreamPeerRTTSet {
		return testConnectStreamPeerRTT
	}
	if c == nil || c.h3 == nil {
		return 0
	}
	if qs := c.h3.QUICStream(); qs != nil {
		if rtt := quic.MasqueConnSmoothedRTT(qs); rtt > 0 {
			return rtt
		}
	}
	return 0
}

func (p ConnectStreamSchedPolicy) DownloadDeliveryWakeBatch(rtt time.Duration) int {
	return sched.DownloadDeliveryWakeBatch(rtt)
}

func (s *bidiScheduler) downloadDeliveryWakeBatch() int {
	if s == nil || s.conn == nil {
		return sched.DownloadDeliveryWakeBatch(0)
	}
	rtt := peerConnectStreamRTT(s.conn)
	avail := 0
	if qs := s.conn.h3.QUICStream(); qs != nil {
		if rtt <= 0 {
			if measured := quic.MasqueConnSmoothedRTT(qs); measured > 0 {
				rtt = measured
			}
		}
		avail = quic.MasqueStreamAvailableSendWindow(qs)
	}
	if rtt < sched.DownloadDeliveryWakeBaseRTT {
		return s.policy.WriteToBufLen
	}
	return sched.DownloadDeliveryWakeBatchClamped(rtt, avail)
}

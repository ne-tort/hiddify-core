package congestion

import (
	"math"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

// Default quic-go uses 10; MASQUE single-stream bulk paths often run cwnd ≫ 10 × MSS while the
// token bucket still capped bursts here — pacing becomes the bottleneck until BW estimate catches up.
// A larger floor lets slow-start / Cubic fill fat pipes on download (server→client) without
// stalling on artificial 10-packet bursts (still bounded by cwnd and congestion).
// Align with MASQUE cubic initialCongestionWindow (192 packets): 48×MSS/RTT caps download ~15 Mbit/s.
const maxBurstSizePackets = 512

// pacerInitialDatagramSize is the MSS used for burst budgeting before PMTU discovery updates
// SetMaxDatagramSize. Align with MASQUE CONNECT-stream first flight (1420 B), not protocol.InitialPacketSize (1280):
// 48×1280 B / RTT caps server→client download near ~15 Mbit/s on typical RTT until the path uses 1420.
const pacerInitialDatagramSize = protocol.ByteCount(1420)

// The pacer implements a token bucket pacing algorithm.
type pacer struct {
	budgetAtLastSent  protocol.ByteCount
	maxDatagramSize   protocol.ByteCount
	lastSentTime      monotime.Time
	adjustedBandwidth func() uint64 // in bytes/s
}

func newPacer(getBandwidth func() Bandwidth) *pacer {
	p := &pacer{
		maxDatagramSize: initialMaxDatagramSize,
		adjustedBandwidth: func() uint64 {
			// Bandwidth is in bits/s. We need the value in bytes/s.
			bw := uint64(getBandwidth() / BytesPerSecond)
			// Use a slightly higher value than the actual measured bandwidth.
			// RTT variations then won't result in under-utilization of the congestion window.
			// Ultimately, this will result in sending packets as acknowledgments are received rather than when timers fire,
			// provided the congestion window is fully utilized and acknowledgments arrive at regular intervals.
			return bw * 5 / 4
		},
	}
	p.budgetAtLastSent = p.maxBurstSize()
	return p
}

func (p *pacer) SentPacket(sendTime monotime.Time, size protocol.ByteCount) {
	budget := p.Budget(sendTime)
	if size >= budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - size
	}
	p.lastSentTime = sendTime
}

func (p *pacer) Budget(now monotime.Time) protocol.ByteCount {
	if p.lastSentTime.IsZero() {
		return p.maxBurstSize()
	}
	delta := now.Sub(p.lastSentTime)
	var added protocol.ByteCount
	if delta > 0 {
		added = p.timeScaledBandwidth(uint64(delta.Nanoseconds()))
	}
	budget := p.budgetAtLastSent + added
	if added > 0 && budget < p.budgetAtLastSent {
		budget = protocol.MaxByteCount
	}
	return min(p.maxBurstSize(), budget)
}

func (p *pacer) pacingMSS() protocol.ByteCount {
	// Until PMTU raises maxDatagramSize, use MASQUE first-flight MSS for burst budgeting.
	if p.maxDatagramSize < pacerInitialDatagramSize {
		return pacerInitialDatagramSize
	}
	return p.maxDatagramSize
}

func (p *pacer) maxBurstSize() protocol.ByteCount {
	return max(
		p.timeScaledBandwidth(uint64((protocol.MinPacingDelay + protocol.TimerGranularity).Nanoseconds())),
		maxBurstSizePackets*p.pacingMSS(),
	)
}

// timeScaledBandwidth calculates the number of bytes that may be sent within
// a given time interval (ns nanoseconds), based on the current bandwidth estimate.
// It caps the scaled value to the maximum allowed burst and handles overflows.
func (p *pacer) timeScaledBandwidth(ns uint64) protocol.ByteCount {
	bw := p.adjustedBandwidth()
	if bw == 0 {
		return 0
	}
	const nsPerSecond = 1e9
	maxBurst := maxBurstSizePackets * p.pacingMSS()
	var scaled protocol.ByteCount
	if ns > math.MaxUint64/bw {
		scaled = maxBurst
	} else {
		scaled = protocol.ByteCount(bw * ns / nsPerSecond)
	}
	return scaled
}

// TimeUntilSend returns when the next packet should be sent.
// It returns zero if a packet can be sent immediately.
func (p *pacer) TimeUntilSend() monotime.Time {
	if p.budgetAtLastSent >= p.maxDatagramSize {
		return 0
	}
	diff := 1e9 * uint64(p.maxDatagramSize-p.budgetAtLastSent)
	bw := p.adjustedBandwidth()
	// We might need to round up this value.
	// Otherwise, we might have a budget (slightly) smaller than the datagram size when the timer expires.
	d := diff / bw
	// this is effectively a math.Ceil, but using only integer math
	if diff%bw > 0 {
		d++
	}
	return p.lastSentTime.Add(max(protocol.MinPacingDelay, time.Duration(d)*time.Nanosecond))
}

func (p *pacer) SetMaxDatagramSize(s protocol.ByteCount) {
	p.maxDatagramSize = s
}

package connectudp

import "time"

// DefaultBenchUDPPayloadLen is the standard synth/localize bench UDP write size (512 B).
const DefaultBenchUDPPayloadLen = 512

// PaceInterval returns the per-packet spacing for a target Mbit/s bench (0 = burst/unlimited).
func PaceInterval(payloadLen int, targetMbit float64) time.Duration {
	if targetMbit <= 0 || payloadLen <= 0 {
		return 0
	}
	seconds := float64(payloadLen*8) / (targetMbit * 1e6)
	return time.Duration(seconds * float64(time.Second))
}

// PaceSleepUntil sleeps until slot (compensating send latency), then advances slot by one interval.
// Mirrors deadline-based pacing in docker bench/udp_masque_send.py (slot += interval, not sleep-after-send).
func PaceSleepUntil(slot *time.Time, payloadLen int, targetMbit float64) {
	if targetMbit <= 0 || payloadLen <= 0 {
		return
	}
	interval := PaceInterval(payloadLen, targetMbit)
	if slot.IsZero() {
		*slot = time.Now()
	}
	if d := time.Until(*slot); d > 0 {
		time.Sleep(d)
	}
	*slot = slot.Add(interval)
}

package connectip

import (
	"os"
	"runtime"
	"strings"
	"time"
)

// h3S2CSendBacklogSoftLimit matches CONNECT-UDP relay h3S2CSendBacklogSoftLimit.
const h3S2CSendBacklogSoftLimit = 256

// h3S2CBacklogDrainMaxSpins bounds Gosched/sleep retries (CONNECT-UDP TransientPressureMaxSpins*64).
const h3S2CBacklogDrainMaxSpins = 8192 * 64

type datagramSendBacklog interface {
	DatagramSendBacklog() int
}

// DatagramSendBacklog returns queued outgoing QUIC DATAGRAM frames when the stream
// exposes them (HTTP/3). Zero for H2 capsule streams / missing API.
func (c *Conn) DatagramSendBacklog() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	str := c.str
	c.mu.Unlock()
	if b, ok := str.(datagramSendBacklog); ok && b != nil {
		return b.DatagramSendBacklog()
	}
	return 0
}

func h3S2CSoftLimitEnabled() bool {
	// Getenv each call (not OnceValue): tests use t.Setenv; DOC LOCK default OFF.
	v := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_H3_S2C_SOFT_LIMIT"))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

// awaitH3S2CSendDrain spins while QUIC DATAGRAM send backlog is at/above the soft limit.
// DOC LOCK (P6-C2 W2-fix 2026-07-20): default OFF — WAN H3 A/B regress ~42/28 → ~32/24.
// Opt-in: MASQUE_CONNECT_IP_H3_S2C_SOFT_LIMIT=1. No-op on H2.
func (c *Conn) awaitH3S2CSendDrain() {
	if c == nil || !h3S2CSoftLimitEnabled() {
		return
	}
	c.mu.Lock()
	str := c.str
	c.mu.Unlock()
	b, ok := str.(datagramSendBacklog)
	if !ok || b == nil {
		return
	}
	cs, _ := str.(proxiedIPDatagramCoalescedSender)
	for spin := 0; b.DatagramSendBacklog() >= h3S2CSendBacklogSoftLimit; spin++ {
		if cs != nil {
			cs.FlushProxiedIPDatagramSend()
		}
		if spin&63 == 63 {
			time.Sleep(time.Microsecond)
		} else {
			runtime.Gosched()
		}
		if spin >= h3S2CBacklogDrainMaxSpins {
			return
		}
	}
}

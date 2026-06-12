package connectip

import "sync/atomic"

// IngressAckWake tracks pending H3 MasqueWakeSend after CONNECT-IP ingress TCP ACK/DATA.
type IngressAckWake struct {
	pending atomic.Bool
}

// NoteFromPacket sets pending when pkt is a narrow TCP wake candidate (ACK-clock / DATA).
func (w *IngressAckWake) NoteFromPacket(pkt []byte) {
	if IPv4TCPIngressWakeCandidate(pkt) {
		w.pending.Store(true)
	}
}

// Schedule marks wake pending without inspecting a packet (e.g. after outbound datagram).
func (w *IngressAckWake) Schedule() {
	w.pending.Store(true)
}

// TakePending consumes a pending wake. Returns false when nothing was scheduled.
func (w *IngressAckWake) TakePending() bool {
	return w.pending.CompareAndSwap(true, false)
}

// Pending reports whether a wake is still scheduled.
func (w *IngressAckWake) Pending() bool {
	return w.pending.Load()
}

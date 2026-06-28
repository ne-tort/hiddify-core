package ingress

import (
	"sync/atomic"

	cipframe "github.com/sagernet/sing-box/transport/masque/connectip/frame"
)

// AckWake tracks pending H3 MasqueWakeSend after CONNECT-IP ingress TCP ACK/DATA.
type AckWake struct {
	pending atomic.Bool
}

// NoteFromPacket sets pending when pkt is a narrow TCP wake candidate (ACK-clock / DATA).
func (w *AckWake) NoteFromPacket(pkt []byte) {
	if cipframe.IPv4TCPIngressWakeCandidate(pkt) {
		w.pending.Store(true)
	}
}

// Schedule marks wake pending without inspecting a packet (e.g. after outbound datagram).
func (w *AckWake) Schedule() {
	w.pending.Store(true)
}

// TakePending consumes a pending wake. Returns false when nothing was scheduled.
func (w *AckWake) TakePending() bool {
	return w.pending.CompareAndSwap(true, false)
}

// Pending reports whether a wake is still scheduled.
func (w *AckWake) Pending() bool {
	return w.pending.Load()
}

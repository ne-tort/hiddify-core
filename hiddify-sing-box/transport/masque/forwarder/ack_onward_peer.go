package forwarder

import (
	"os"
	"strings"
)

// ACK-onward-peer DIAG (colo nested BBR): delay nested wire ACK until onward
// TCP peer has ACKed bytes (TCP_INFO Bytes_acked) — not accept into c2sCh, not Flush.
// Env: MASQUE_CONNECT_IP_ACK_ONWARD_PEER=1
// Tip KEEP = off. Differs from ACK_AFTER_FLUSH (kernel sndbuf only → colo FLAT).

func ackOnwardPeerEnabled() bool {
	v := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_ACK_ONWARD_PEER"))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

// ackWireLagEnabled: wire ACK cursor lags rcvNxt (Flush and/or onward-peer DIAG).
func ackWireLagEnabled() bool {
	return ackAfterFlushEnabled() || ackOnwardPeerEnabled()
}

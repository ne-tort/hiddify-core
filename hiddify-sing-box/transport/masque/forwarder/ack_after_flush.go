package forwarder

import (
	"os"
	"strconv"
	"strings"
)

// ACK-after-Flush DIAG (colo nested BBR): delay nested ACK / write-credit until
// bytes are Flushed to onward TCP — not when accepted into c2sCh.
// Env: MASQUE_CONNECT_IP_ACK_AFTER_FLUSH=1
// Optional credit (bytes accepted ahead of wire ACK): MASQUE_CONNECT_IP_ACK_FLUSH_CREDIT (default 64KiB).

const defaultAckFlushCredit = 64 << 10

func ackAfterFlushEnabled() bool {
	v := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_ACK_AFTER_FLUSH"))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

func ackFlushCreditBytes() uint32 {
	if c := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_ACK_FLUSH_CREDIT")); c != "" {
		if n, err := strconv.Atoi(c); err == nil && n >= 16<<10 && n <= 4<<20 {
			return uint32(n)
		}
	}
	return defaultAckFlushCredit
}

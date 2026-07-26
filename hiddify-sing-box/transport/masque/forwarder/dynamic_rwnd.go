package forwarder

import (
	"os"
	"strings"
)

// Dynamic advertised rcv window DIAG (colo nested BBR):
// advertise free C2S absorb (c2sCh / pendingRemote) instead of always 65535×WS.
// Differs from static RCVWND cap (REJECT): window tracks drain and re-opens.
// Env: MASQUE_CONNECT_IP_DYNAMIC_RWND=1
// Pair with MASQUE_CONNECT_IP_C2S_DEPTH≈512 for BDP-scale absorb (tip depth=16384
// still advertises multi-MiB at start → same early overshoot).

func dynamicRwndEnabled() bool {
	v := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_DYNAMIC_RWND"))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

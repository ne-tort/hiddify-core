package pump

import (
	"strings"

	"github.com/sagernet/sing-box/transport/masque/connectip/netstack"
)

// IsRetryablePacketReadError classifies transient CONNECT-IP ReadPacket failures.
func IsRetryablePacketReadError(err error) bool {
	if netstack.IsRetryablePacketReadError(err) {
		return true
	}
	// Shared QUIC stream: upload TCP close can briefly surface this on LoopOut ReadPacket
	// during same-session download; retry instead of exiting RunTunnel (native L3 pump restart flake).
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "use of closed network connection") {
		return true
	}
	return false
}

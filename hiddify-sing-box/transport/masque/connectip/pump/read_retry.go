package pump

import "github.com/sagernet/sing-box/transport/masque/connectip/netstack"

// IsRetryablePacketReadError classifies transient CONNECT-IP ReadPacket failures.
func IsRetryablePacketReadError(err error) bool {
	return netstack.IsRetryablePacketReadError(err)
}

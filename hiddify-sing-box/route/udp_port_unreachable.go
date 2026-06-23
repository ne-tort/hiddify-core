package route

import (
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	cudpsplit "github.com/sagernet/sing-box/transport/masque/connectudp/split"
	M "github.com/sagernet/sing/common/metadata"
)

func isUDPPortUnreachable(err error) bool {
	return cudpsplit.IsPortUnreachable(err) || cip.IsICMPPortUnreachable(err)
}

func udpPortUnreachableRemote(err error, fallback M.Socksaddr) M.Socksaddr {
	if remote := cudpsplit.PortUnreachableRemote(err, fallback); remote.IsValid() {
		return remote
	}
	return cip.ICMPPortUnreachableRemote(err, fallback)
}

package route

import (
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	cudp "github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

func isUDPPortUnreachable(err error) bool {
	return cudp.IsPortUnreachable(err) || cip.IsICMPPortUnreachable(err)
}

func udpPortUnreachableRemote(err error, fallback M.Socksaddr) M.Socksaddr {
	if remote := cudp.PortUnreachableRemote(err, fallback); remote.IsValid() {
		return remote
	}
	return cip.ICMPPortUnreachableRemote(err, fallback)
}

package route

import (
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func deliverUDPPortUnreachableToTUN(inbound N.PacketWriter, remote M.Socksaddr) {
	for u := any(inbound); u != nil; {
		if w, ok := common.Cast[tun.UDPPortUnreachableFeedback](u); ok {
			if err := w.WriteUDPPortUnreachable(remote); err == nil {
				return
			}
		}
		up, ok := u.(interface{ Upstream() any })
		if !ok {
			break
		}
		next := up.Upstream()
		if next == nil || next == u {
			break
		}
		u = next
	}
}

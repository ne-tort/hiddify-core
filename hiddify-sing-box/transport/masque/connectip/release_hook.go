package connectip

import (
	cipgo "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/transport/masque/pathbuild"
)

func init() {
	// Release hook is registered once in egress_reexport.go (avoid dual init).
	cipgo.SetIPScopeOpener(func(opaque string) (string, uint8, error) {
		return pathbuild.OpenIPScope(pathbuild.ActiveKey(true), opaque)
	})
}

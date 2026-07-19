package connectip

import (
	connectipgo "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/transport/masque/pathbuild"
)

func init() {
	// ParseRequest lives in vendor; opaque crypto stays in pathbuild (P1-6 / F5-T2).
	connectipgo.SetIPScopeOpener(func(opaque string) (string, uint8, error) {
		return pathbuild.OpenIPScope(pathbuild.ActiveKey(true), opaque)
	})
}

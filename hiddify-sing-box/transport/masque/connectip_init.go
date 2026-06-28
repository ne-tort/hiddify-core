package masque

import (
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/sagernet/sing-box/transport/masque/session"
)

func init() {
	cip.SetErrors(cip.Errors{
		StackInit:      session.ErrTCPStackInit,
		Dial:           session.ErrTCPDial,
		Closed:         session.ErrLifecycleClosed,
		DialRequiresIP: session.ErrTCPOverConnectIP,
		Transport:      session.ErrTransportInit,
		Capability:     session.ErrCapability,
	})
	cip.SetObs(cip.CounterObsHooks())
}

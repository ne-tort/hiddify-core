package masque

import (
	"github.com/sagernet/sing-box/transport/masque/session"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

func init() {
	strm.SetErrors(strm.Errors{
		TCPConnectStreamFailed: session.ErrTCPConnectStreamFailed,
		Capability:             session.ErrCapability,
	})
}

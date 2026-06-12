package masque

import (
	"github.com/sagernet/sing-box/protocol/masque/server"
	TM "github.com/sagernet/sing-box/transport/masque"
)

func init() {
	TM.RegisterConnectIPServerParseDropSupplier(server.ConnectIPServerParseDropTotal)
}

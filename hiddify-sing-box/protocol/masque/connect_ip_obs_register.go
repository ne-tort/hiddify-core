package masque

import (
	"github.com/sagernet/sing-box/protocol/masque/server"
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
)

func init() {
	cip.RegisterServerParseDropSupplier(server.ConnectIPServerParseDropTotal)
}

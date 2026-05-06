package masque

import TM "github.com/sagernet/sing-box/transport/masque"

func init() {
	TM.RegisterConnectIPServerParseDropSupplier(ConnectIPServerParseDropTotal)
}

package client

import h2pkg "github.com/sagernet/sing-box/transport/masque/stream/client/h2"

type (
	H2Host         = h2pkg.Host
	H2Hooks        = h2pkg.Hooks
	H2Auth         = h2pkg.Auth
	H2Wire         = h2pkg.Wire
	H2DialInput    = h2pkg.DialInput
	SessionH2Host  = h2pkg.SessionHost
)

var (
	NewH2Hooks = h2pkg.NewHooks
	DialHTTP2  = h2pkg.DialHTTP2
)

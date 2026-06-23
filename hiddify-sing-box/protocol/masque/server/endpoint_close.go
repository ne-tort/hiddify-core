package server

import (
	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	btls "github.com/sagernet/sing-box/common/tls"
)

// MasqueEndpointCloseInput carries runtime resources held by ServerEndpoint.Close.
type MasqueEndpointCloseInput struct {
	Stack         MasqueStack
	UDPProxy      *cudprelay.Proxy
	SingServerTLS btls.ServerConfig
}

// CloseMasqueEndpoint tears down the dual-bind MASQUE server runtime.
func CloseMasqueEndpoint(in MasqueEndpointCloseInput) error {
	return ShutdownMasqueEndpoint(ShutdownMasqueEndpointConfig{
		Stack:         &in.Stack,
		UDPProxy:      in.UDPProxy,
		SingServerTLS: in.SingServerTLS,
	})
}

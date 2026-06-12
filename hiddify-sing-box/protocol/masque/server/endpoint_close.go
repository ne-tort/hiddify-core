package server

import (
	qmasque "github.com/quic-go/masque-go"
	btls "github.com/sagernet/sing-box/common/tls"
	TM "github.com/sagernet/sing-box/transport/masque"
)

// MasqueEndpointCloseInput carries runtime resources held by ServerEndpoint.Close.
type MasqueEndpointCloseInput struct {
	AuthorityThin *TM.AuthorityHTTPServer
	Stack         MasqueStack
	UDPProxy      *qmasque.Proxy
	SingServerTLS btls.ServerConfig
}

// CloseMasqueEndpoint tears down authority-thin or full dual-bind runtime.
// Authority-thin path closes only the HTTP/3 listener; full stack delegates to ShutdownMasqueEndpoint.
func CloseMasqueEndpoint(in MasqueEndpointCloseInput) error {
	if in.AuthorityThin != nil {
		return in.AuthorityThin.Close()
	}
	return ShutdownMasqueEndpoint(ShutdownMasqueEndpointConfig{
		Stack:         &in.Stack,
		UDPProxy:      in.UDPProxy,
		SingServerTLS: in.SingServerTLS,
	})
}

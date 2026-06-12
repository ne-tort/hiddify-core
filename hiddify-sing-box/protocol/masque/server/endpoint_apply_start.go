package server

import (
	"net"
	"net/http"

	"github.com/quic-go/quic-go/http3"
	btls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/protocol/masque/auth"
	TM "github.com/sagernet/sing-box/transport/masque"
)

// AppliedMasqueEndpointStart maps RunMasqueEndpointStart output onto ServerEndpoint fields.
type AppliedMasqueEndpointStart struct {
	CompiledAuth   *auth.Compiled
	SingServerTLS  btls.ServerConfig
	AuthorityThin  *TM.AuthorityHTTPServer
	H3Server       *http3.Server
	PacketConn     net.PacketConn
	HTTP2Server    *http.Server
	TCPTLSListener net.Listener
}

// MapMasqueEndpointStartResult projects a successful start outcome onto adapter runtime fields.
func MapMasqueEndpointStartResult(out MasqueEndpointStartResult) AppliedMasqueEndpointStart {
	applied := AppliedMasqueEndpointStart{
		CompiledAuth:  out.CompiledAuth,
		SingServerTLS: out.SingServerTLS,
		AuthorityThin: out.AuthorityThin,
	}
	if out.Stack != nil {
		applied.H3Server = out.Stack.H3Server
		applied.PacketConn = out.Stack.PacketConn
		applied.HTTP2Server = out.Stack.HTTP2Server
		applied.TCPTLSListener = out.Stack.TCPTLSListener
	}
	return applied
}

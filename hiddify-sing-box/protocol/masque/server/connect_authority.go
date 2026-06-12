package server

import (
	"context"
	"net"
	"net/http"

	"github.com/sagernet/sing-box/option"
)

// TCPConnectAuthorityHost carries CONNECT-by-authority handler dependencies from the parent endpoint.
type TCPConnectAuthorityHost struct {
	Options   option.MasqueEndpointOptions
	Dialer    net.Dialer
	Authorize func(*http.Request) bool
}

// HandleTCPConnectAuthority serves Invisv-style CONNECT https://target:port/ and relays onward TCP.
func HandleTCPConnectAuthority(host TCPConnectAuthorityHost, w http.ResponseWriter, r *http.Request) {
	policy := CONNECTAuthorityPolicy{
		AllowPrivateTargets: host.Options.AllowPrivateTargets,
		AllowedPorts:        host.Options.AllowedTargetPorts,
		BlockedPorts:        host.Options.BlockedTargetPorts,
		Authorize:           host.Authorize,
		ResolveHost: func(ctx context.Context, targetHost string) (string, error) {
			return ResolveTCPTargetForDial(ctx, targetHost, host.Options.AllowPrivateTargets)
		},
	}
	ServeCONNECTAuthority(w, r, policy, host.Dialer.DialContext)
}

func tcpConnectAuthorityHost(host MuxHost) TCPConnectAuthorityHost {
	return TCPConnectAuthorityHost{
		Options:   host.Options,
		Dialer:    host.Dialer,
		Authorize: host.Authorize,
	}
}

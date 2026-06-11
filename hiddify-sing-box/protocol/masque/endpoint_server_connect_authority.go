package masque

import (
	"context"
	"net/http"

	TM "github.com/sagernet/sing-box/transport/masque"
)

func (e *ServerEndpoint) handleTCPConnectAuthority(w http.ResponseWriter, r *http.Request) {
	policy := TM.CONNECTAuthorityPolicy{
		AllowPrivateTargets: e.options.AllowPrivateTargets,
		AllowedPorts:        e.options.AllowedTargetPorts,
		BlockedPorts:        e.options.BlockedTargetPorts,
		Authorize:           e.authorizeRequest,
		ResolveHost: func(ctx context.Context, host string) (string, error) {
			return resolveTCPTargetForDial(ctx, host, e.options.AllowPrivateTargets)
		},
	}
	TM.ServeCONNECTAuthority(w, r, policy, e.dialer.DialContext)
}

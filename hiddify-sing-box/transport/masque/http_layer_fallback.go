package masque

import "github.com/sagernet/sing-box/transport/masque/httpx"

func init() {
	httpx.RegisterNonSwitchableSentinel(
		ErrConnectUDPTemplateNotConfigured,
		ErrConnectIPTemplateNotConfigured,
		ErrAuthFailed,
	)
}

// IsMasqueHTTPLayerSwitchableFailure classifies dataplane/handshake faults where trying the alternate H2/H3 overlay may help.
// Callers MUST NOT retry on authoritative HTTP auth/policy errors or explicit configuration rejects.
func IsMasqueHTTPLayerSwitchableFailure(err error) bool {
	return httpx.IsLayerSwitchableFailure(err)
}

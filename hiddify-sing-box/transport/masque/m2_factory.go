package masque

import (
	"context"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// M2ClientFactory keeps the transport contract stable while enforcing
// transport-mode capability gates expected by MASQUE endpoint options.
type M2ClientFactory struct {
	Fallback ClientFactory
}

func (f M2ClientFactory) NewSession(ctx context.Context, options ClientOptions) (ClientSession, error) {
	backend := f.Fallback
	if backend == nil {
		backend = DirectClientFactory{}
	}
	switch options.TransportMode {
	case option.MasqueTransportModeConnectUDP:
		// CONNECT-UDP only path.
		return backend.NewSession(ctx, options)
	case option.MasqueTransportModeConnectIP:
		// CONNECT-IP path is intentionally separated in contract level and can
		// be backed by a dedicated implementation without changing protocol layer.
		return backend.NewSession(ctx, options)
	case option.MasqueTransportModeAuto, "":
		return backend.NewSession(ctx, options)
	default:
		return nil, E.New("unsupported transport_mode: ", options.TransportMode)
	}
}


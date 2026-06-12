package masque

import (
	"context"

	"github.com/sagernet/sing-box/transport/masque/session"
)

func init() {
	session.BuildCoreSession = buildCoreSession
	session.BuildDirectSession = session.NewDirectSession
}

func buildCoreSession(ctx context.Context, options session.ClientOptions) (session.ClientSession, error) {
	templateUDP, templateIP, templateTCP, err := session.BuildTemplates(options, masqueTemplateHooks())
	if err != nil {
		err = joinTemplateCapability(err)
	}
	if err != nil {
		return nil, err
	}
	cs, udpLayer := session.BootstrapCoreSession(options, templateUDP, templateIP, templateTCP)
	core := &coreSession{CoreSession: cs}
	core.UDPHTTPLayer.Store(udpLayer)
	return core, nil
}

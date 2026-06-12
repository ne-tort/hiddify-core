package server

import (
	"crypto/tls"
	"net/http"

	TM "github.com/sagernet/sing-box/transport/masque"
	E "github.com/sagernet/sing/common/exceptions"
)

// AuthorityThinListenHooks observes authority thin server lifecycle from the endpoint adapter.
type AuthorityThinListenHooks struct {
	IsClosing    func() bool
	OnServeError func(err error)
	OnServeEnd   func()
}

// LaunchAuthorityThinHTTPServer starts thin authority HTTP/3 in background (masque-thin-server parity).
func LaunchAuthorityThinHTTPServer(handler http.Handler, listenAddr string, tlsCfg *tls.Config, hooks AuthorityThinListenHooks) (*TM.AuthorityHTTPServer, error) {
	as, err := TM.StartAuthorityHTTPServer(TM.AuthorityListenOptions{
		ListenAddr:      listenAddr,
		TLSConfig:       tlsCfg,
		Handler:         handler,
		EnableDatagrams: false,
		QUICConfig:      TM.MasqueAuthorityHTTPServerQUICConfig(),
	})
	if err != nil {
		return nil, E.Cause(err, "masque authority thin http3 listen")
	}
	go func() {
		serveErr := as.Serve()
		isClosing := hooks.IsClosing != nil && hooks.IsClosing()
		if serveErr != nil && !(isClosing && ExpectedShutdownError(serveErr)) {
			if hooks.OnServeError != nil {
				hooks.OnServeError(serveErr)
			}
		}
		if hooks.OnServeEnd != nil {
			hooks.OnServeEnd()
		}
	}()
	return as, nil
}

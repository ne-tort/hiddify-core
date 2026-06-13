package server

import (
	"net/http"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque/auth"
)

// AuthorizeMasqueRequest applies compiled server ACL to r.
// When compiled is nil and the endpoint has not started listening, options are compiled lazily
// so unit tests can call handlers without Start(). Compile errors fail closed (deny).
func AuthorizeMasqueRequest(r *http.Request, compiled **auth.Compiled, options option.MasqueEndpointOptions, listenActive bool) bool {
	a := *compiled
	if a == nil && !listenActive {
		var err error
		a, err = auth.Compile(options)
		if err != nil {
			return false
		}
		if a == nil {
			return true
		}
		*compiled = a
	}
	if a == nil {
		return true
	}
	return a.AuthorizeRequest(r)
}

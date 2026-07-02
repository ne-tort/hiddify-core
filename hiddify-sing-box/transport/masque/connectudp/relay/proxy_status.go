package relay

import (
	"net/http"

	"github.com/dunglas/httpsfv"
)

// addProxyStatusNextHop sets Proxy-Status next-hop on a successful CONNECT-UDP response (RFC 9298).
func addProxyStatusNextHop(w http.ResponseWriter, authorityHost, target string) error {
	item := httpsfv.NewItem(authorityHost)
	item.Params.Add("next-hop", target)
	val, err := httpsfv.Marshal(item)
	if err != nil {
		return err
	}
	w.Header().Add("Proxy-Status", val)
	return nil
}

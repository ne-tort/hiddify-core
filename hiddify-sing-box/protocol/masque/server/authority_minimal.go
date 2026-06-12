package server

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/sagernet/sing-box/option"
)

// AuthorityServerMinimalForOptions reports thin authority-only mux (no CONNECT-UDP/IP templates).
func AuthorityServerMinimalForOptions(o option.MasqueEndpointOptions) bool {
	if AuthorityServerMinimal() {
		return true
	}
	return strings.TrimSpace(o.TemplateUDP) == "" && strings.TrimSpace(o.TemplateIP) == ""
}

// NewAuthorityMinimalHandler serves CONNECT-by-authority only (Invisv thin server parity).
func NewAuthorityMinimalHandler(host TCPConnectAuthorityHost) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("MASQUE_TRACE_TCP") == "1" {
			fmt.Fprintf(os.Stderr, "masque authority minimal http method=%s url=%s host=%s\n",
				r.Method, r.URL.String(), r.Host)
		}
		if r.Method == http.MethodConnect {
			HandleTCPConnectAuthority(host, w, r)
			return
		}
		http.NotFound(w, r)
	})
}

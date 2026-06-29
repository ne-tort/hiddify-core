package relay

import (
	"io"
	"net/http"
)

// relayLogHijackEnabled is hardcoded off in prod (zero MASQUE_RELAY_LOG_HIJACK env).
var relayLogHijackEnabled = false

func logRelayHijackProbe(reqBody io.ReadCloser, responseWriter http.ResponseWriter) {
	if !relayLogHijackEnabled {
		return
	}
}

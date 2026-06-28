package relay

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/quic-go/quic-go/http3"
)

var relayLogHijackEnabled = strings.TrimSpace(os.Getenv("MASQUE_RELAY_LOG_HIJACK")) == "1"

func logRelayHijackProbe(reqBody io.ReadCloser, responseWriter http.ResponseWriter) {
	if !relayLogHijackEnabled {
		return
	}
	_, wHS := responseWriter.(http3.HTTPStreamer)
	_, bHS := reqBody.(http3.HTTPStreamer)
	fmt.Fprintf(os.Stderr, "masque relay hijack probe writer_httpstreamer=%v body_httpstreamer=%v\n", wHS, bHS)
}

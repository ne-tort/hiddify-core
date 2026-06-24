package http2

import (
	"os"
	"strings"
)

func init() {
	// Runs after http2.go init (filename order). MASQUE requires RFC 8441 Extended CONNECT
	// for H2 CONNECT-UDP / CONNECT-stream; upstream defaults off (golang.org/issue/71128).
	// Opt-out: GODEBUG=http2xconnect=0
	if strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=0") {
		return
	}
	disableExtendedConnectProtocol = false
}

// Package http2xconnect ensures golang.org/x/net/http2 enables RFC 8441 (SETTINGS_ENABLE_CONNECT_PROTOCOL)
// before the http2 package's init reads GODEBUG. MASQUE uses Extended CONNECT for H2 CONNECT-UDP / CONNECT-stream;
// upstream x/net defaults to opt-in via GODEBUG=http2xconnect=1 (see golang.org/issue/71128).
//
// Import this package blank-only from protocol/masque or transport/masque so it initializes before golang.org/x/net/http2.
package http2xconnect

import (
	"os"
	"strings"
)

func init() {
	ensureHTTP2ExtendedConnectEnabled()
}

func ensureHTTP2ExtendedConnectEnabled() {
	e := os.Getenv("GODEBUG")
	if strings.Contains(e, "http2xconnect=1") {
		return
	}
	if e == "" {
		os.Setenv("GODEBUG", "http2xconnect=1")
		return
	}
	os.Setenv("GODEBUG", e+",http2xconnect=1")
}

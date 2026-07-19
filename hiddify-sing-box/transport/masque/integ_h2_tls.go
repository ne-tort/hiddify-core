package masque

import (
	"crypto/tls"
	"testing"

	"golang.org/x/net/http2"
)

// InProcessH2TestTLS returns a shared leaf cert for in-process HTTP/2 MASQUE servers
// (CONNECT-IP / CONNECT-UDP Extended CONNECT over TLS).
func InProcessH2TestTLS(tb testing.TB) *tls.Config {
	tb.Helper()
	if connectUDPTestTLS == nil {
		tb.Fatal("InProcessH2TestTLS: shared test TLS not initialized")
	}
	cfg := connectUDPTestTLS.Clone()
	cfg.NextProtos = []string{http2.NextProtoTLS, "http/1.1"}
	return cfg
}

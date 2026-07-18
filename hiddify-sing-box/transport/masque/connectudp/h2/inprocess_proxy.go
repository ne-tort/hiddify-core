package h2

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	cudpframe "github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

// StartInProcessConnectUDPProxy serves HTTPS CONNECT-UDP on an ephemeral TCP port.
// Shared by connectudp/h2 integration tests and masque-package inttest harness (UDP-STRUCT-19).
func StartInProcessConnectUDPProxy(tb testing.TB, serverTLS *tls.Config, sessions *SessionRegistry) int {
	tb.Helper()
	if serverTLS == nil {
		tb.Fatal("StartInProcessConnectUDPProxy: serverTLS is nil")
	}
	tlsCfg := serverTLS.Clone()
	tlsCfg.NextProtos = []string{http2.NextProtoTLS, "http/1.1"}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen tcp: %v", err)
	}
	proxyPort := ln.Addr().(*net.TCPAddr).Port
	// Trailing slash matches pathbuild.FullURITemplate (prod client expand).
	templateRaw := fmt.Sprintf("https://127.0.0.1:%d/masque/udp/{target_host}/{target_port}/", proxyPort)
	udpTemplate, err := uritemplate.New(templateRaw)
	if err != nil {
		tb.Fatalf("udp template: %v", err)
	}

	cfg := ServeConnectUDPConfig{Sessions: sessions}

	mux := http.NewServeMux()
	// pathbuild FullURITemplate expands with a trailing slash; match both shapes.
	serve := func(w http.ResponseWriter, r *http.Request) {
		req, err := cudpframe.ParseRequest(r, udpTemplate)
		if err != nil {
			if pe, ok := err.(*cudpframe.RequestParseError); ok {
				w.WriteHeader(pe.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ServeConnectUDP(w, r, req.Target, req.Host, cfg)
	}
	mux.HandleFunc("/masque/udp/{target_host}/{target_port}", serve)
	mux.HandleFunc("/masque/udp/{target_host}/{target_port}/", serve)

	tlsLn := tls.NewListener(ln, tlsCfg)
	srv := &http.Server{Handler: mux}
	if err := http2.ConfigureServer(srv, h2c.BulkHTTP2ServerConfig()); err != nil {
		tb.Fatalf("configure http2 server: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = srv.Serve(tlsLn)
	}()
	tb.Cleanup(func() {
		_ = srv.Close()
		wg.Wait()
	})
	time.Sleep(20 * time.Millisecond)
	return proxyPort
}

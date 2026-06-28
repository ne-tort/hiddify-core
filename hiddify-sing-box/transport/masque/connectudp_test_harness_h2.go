package masque

// In-process H2 CONNECT-UDP HTTPS proxy for masque-package harness/localize tests (W-UDP-4 PR3).

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

func startInProcessH2UDPConnectProxy(t testing.TB) int {
	t.Helper()
	serverTLS := connectUDPTestTLS.Clone()
	serverTLS.NextProtos = []string{http2.NextProtoTLS, "http/1.1"}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	proxyPort := ln.Addr().(*net.TCPAddr).Port
	templateRaw := fmt.Sprintf("https://127.0.0.1:%d/masque/udp/{target_host}/{target_port}", proxyPort)
	udpTemplate, err := uritemplate.New(templateRaw)
	if err != nil {
		t.Fatalf("udp template: %v", err)
	}
	var udpProxy cudprelay.Proxy
	t.Cleanup(func() { _ = udpProxy.Close() })

	mux := http.NewServeMux()
	mux.HandleFunc("/masque/udp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		serveConnectUDPProdHandler(w, r, udpTemplate, &udpProxy)
	})
	tlsLn := tls.NewListener(ln, serverTLS)
	srv := &http.Server{Handler: mux}
	if err := http2.ConfigureServer(srv, h2c.BulkHTTP2ServerConfig()); err != nil {
		t.Fatalf("configure http2 server: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = srv.Serve(tlsLn)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		wg.Wait()
	})
	time.Sleep(20 * time.Millisecond)
	return tlsLn.Addr().(*net.TCPAddr).Port
}

func newH2ConnectUDPSession(t *testing.T, proxyPort int, link h2TransportLink) (ClientSession, context.Context) {
	t.Helper()
	if link == nil {
		link = instantH2Link{}
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(proxyPort),
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
		MasqueQUICCryptoTLS:      &tls.Config{InsecureSkipVerify: true},
		TCPDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := baseDial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return link.wrapTCP(conn), nil
		},
	})
	if err != nil {
		t.Fatalf("new h2 connect-udp session: %v", err)
	}
	t.Cleanup(func() { closeConnectUDPTestSession(session) })
	return session, waitCtx
}

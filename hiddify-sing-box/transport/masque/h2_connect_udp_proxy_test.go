package masque

// In-process H2 CONNECT-UDP HTTPS proxy for masque-package harness/localize tests.
// connectudp/ integration tests use connectudp/h2_integration_test.go (DialH2Overlay path).

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	cudp "github.com/sagernet/sing-box/transport/masque/connectudp"
	"golang.org/x/net/http2"
)

func startInProcessH2UDPConnectProxy(t *testing.T) int {
	t.Helper()
	serverTLS := connectUDPTestTLS.Clone()
	serverTLS.NextProtos = []string{http2.NextProtoTLS, "http/1.1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/masque/udp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if strings.TrimSpace(r.Header.Get(":protocol")) != cudp.H2ConnectProto {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		host := r.PathValue("target_host")
		port := r.PathValue("target_port")
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = http.NewResponseController(w).EnableFullDuplex()
		w.Header().Set(http3.CapsuleProtocolHeader, CapsuleProtocolHeaderValueH2())
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_ = cudp.ServeH2(w, r, conn)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	tlsLn := tls.NewListener(ln, serverTLS)
	srv := &http.Server{Handler: mux}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
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

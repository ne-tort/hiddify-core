package masque

// In-process HTTP/3 CONNECT-stream relay proxy for inttest/localize (W-STR-4 PR6).

import (
	"context"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

func connectStreamRelayHandler(targetHost, targetPort string, r *http.Request, w http.ResponseWriter) {
	leg := strm.ConnectStreamLegFromRequest(r)
	pairKey := strm.ConnectStreamPairKeyFromRequest(r, targetHost, targetPort)
	dialOnward := func(ctx context.Context) (net.Conn, error) {
		upstream, err := net.DialTimeout("tcp", net.JoinHostPort(targetHost, targetPort), 2*time.Second)
		if err != nil {
			return nil, err
		}
		_ = upstream.SetDeadline(time.Now().Add(30 * time.Second))
		return upstream, nil
	}
	upstream, release, err := strm.AcquireDualLegOnward(r.Context(), leg, pairKey, dialOnward)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer release()
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	_ = strm.RelayTCPTunnel(r.Context(), upstream, r.Body, w, leg)
}

func startInProcessTCPConnectProxy(tb testing.TB, handler func(targetHost, targetPort string, r *http.Request, w http.ResponseWriter)) int {
	tb.Helper()
	quicConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		tb.Fatalf("listen quic udp: %v", err)
	}
	proxyPort := quicConn.LocalAddr().(*net.UDPAddr).Port

	mux := http.NewServeMux()
	mux.HandleFunc("/masque/tcp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		handler(r.PathValue("target_host"), r.PathValue("target_port"), r, w)
	})
	server := http3.Server{
		TLSConfig:       connectUDPTestTLS,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: true,
		Handler:         mux,
	}
	var serveWG sync.WaitGroup
	serveWG.Add(1)
	go func() {
		defer serveWG.Done()
		_ = server.Serve(quicConn)
	}()
	tb.Cleanup(func() {
		_ = server.Close()
		serveWG.Wait()
		_ = quicConn.Close()
	})
	time.Sleep(20 * time.Millisecond)
	return proxyPort
}

func startInProcessTCPConnectStreamRelayProxy(tb testing.TB) int {
	return startInProcessTCPConnectProxy(tb, connectStreamRelayHandler)
}

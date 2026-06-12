package masque

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/session"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	"golang.org/x/net/http2"
)

// startInProcessH2TCPConnectStreamProxy serves HTTPS + HTTP/2 Extended CONNECT-stream and relays TCP.
func startInProcessH2TCPConnectStreamProxy(t *testing.T) int {
	t.Helper()
	serverTLS := connectUDPTestTLS.Clone()
	serverTLS.NextProtos = []string{http2.NextProtoTLS, "http/1.1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/masque/tcp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if p := r.Header.Get(":protocol"); p != "" && p != strm.H2ConnectStreamProto {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		host := r.PathValue("target_host")
		port := r.PathValue("target_port")
		target, err := net.Dial("tcp", net.JoinHostPort(host, port))
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = http.NewResponseController(w).EnableFullDuplex()
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		relayErr := RelayTCPTunnel(r.Context(), target, r.Body, w)
		_ = target.Close()
		if relayErr != nil && relayErr != io.EOF {
			t.Logf("relay finished: %v", relayErr)
		}
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	tlsLn := tls.NewListener(ln, serverTLS)
	srv := &http.Server{Handler: mux}
	if err := http2.ConfigureServer(srv, MasqueBulkHTTP2ServerConfig()); err != nil {
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

// TestH2ConnectStreamTCPUploadInProcess verifies Extended CONNECT-stream upload (iperf-shaped bulk).
func TestH2ConnectStreamTCPUploadInProcess(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	t.Cleanup(func() { _ = targetLn.Close() })
	targetPort := targetLn.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()

	proxyPort := startInProcessH2TCPConnectStreamProxy(t)
	rawURL := "https://127.0.0.1:" + strconv.Itoa(proxyPort) + "/masque/tcp/127.0.0.1/" + strconv.Itoa(targetPort)
	tcpURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	s := newTestCoreSession(session.CoreSession{
			Options: ClientOptions{
			Server:              "127.0.0.1",
			ServerPort:          uint16(proxyPort),
			MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
			TCPTransport:        option.MasqueTCPTransportConnectStream,
		},
		})
	s.Options.TCPDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	s.UDPHTTPLayer.Store(option.MasqueHTTPLayerH2)

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	conn, err := s.dialTCPStreamH2(ctx, tcpURL, s.Options, "127.0.0.1", M.ParseSocksaddrHostPort("127.0.0.1", uint16(targetPort)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	payload := make([]byte, 256*1024)
	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(payload[:64])
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)

	uploadDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, io.LimitReader(&zeroReader{}, 512*1024))
		uploadDone <- err
	}()

	select {
	case err := <-uploadDone:
		if err != nil && err != io.EOF {
			t.Fatalf("upload: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("upload blocked >8s (H2 CONNECT-stream body stall)")
	}
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

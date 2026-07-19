package inttest

// In-process CONNECT-IP HTTP/2 harness (P1-9 / F3-T4).

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
	"github.com/sagernet/sing-box/protocol/masque/server"
	"github.com/sagernet/sing-box/transport/masque"
	mh2 "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"

	_ "github.com/sagernet/sing-box/internal/http2xconnect"
)

// NativeH2ClientOptions builds ClientOptions for native connect_ip on in-proc H2 server.
func NativeH2ClientOptions(proxyPort int) masque.ClientOptions {
	return masque.ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(proxyPort),
		PathIP:                   "/masque/ip",
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
		MasqueQUICCryptoTLS: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{http2.NextProtoTLS},
		},
		DataplaneMode:    option.MasqueDataplaneConnectIP,
		ProfileLocalIPv4: NativeProfileLocalIPv4,
		TCPDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
}

func StartNativeConnectIPH2Server(tb testing.TB) int {
	tb.Helper()
	return NewNativeConnectIPH2Server(tb).Port()
}

// NativeConnectIPH2Server is a restartable in-proc CONNECT-IP H2 server (P1-9).
type NativeConnectIPH2Server struct {
	port    int
	tcpLn   net.Listener
	srv     *http.Server
	serveWG sync.WaitGroup
}

// NewNativeConnectIPH2Server starts an H2 CONNECT-IP server; tb.Cleanup stops it.
func NewNativeConnectIPH2Server(tb testing.TB) *NativeConnectIPH2Server {
	tb.Helper()
	s := &NativeConnectIPH2Server{}
	if err := s.launch(tb, 0); err != nil {
		tb.Fatalf("launch h2 server: %v", err)
	}
	tb.Cleanup(func() { _ = s.Stop() })
	return s
}

func (s *NativeConnectIPH2Server) Port() int { return s.port }

func (s *NativeConnectIPH2Server) Stop() error {
	if s.srv != nil {
		_ = s.srv.Close()
	}
	s.serveWG.Wait()
	if s.tcpLn != nil {
		_ = s.tcpLn.Close()
		s.tcpLn = nil
	}
	s.srv = nil
	return nil
}

// Restart stops and relaunches the server on the same TCP port (P2-13 mid-session recycle parity with H3).
func (s *NativeConnectIPH2Server) Restart(tb testing.TB) {
	tb.Helper()
	keepPort := s.port
	_ = s.Stop()
	time.Sleep(50 * time.Millisecond)
	if err := s.launch(tb, keepPort); err != nil {
		tb.Fatalf("restart h2 server: %v", err)
	}
}

func (s *NativeConnectIPH2Server) launch(tb testing.TB, fixedPort int) error {
	addr := "127.0.0.1:0"
	if fixedPort > 0 {
		addr = fmt.Sprintf("127.0.0.1:%d", fixedPort)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	proxyPort := ln.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()
	ipTemplateRaw := fmt.Sprintf("https://127.0.0.1:%d/masque/ip", proxyPort)
	ipTemplate, err := uritemplate.New(ipTemplateRaw)
	if err != nil {
		_ = ln.Close()
		return err
	}
	host := server.ConnectIPHandlerHost{
		Tag:     "native-smoke-h2",
		Type:    "masque",
		Options: option.MasqueEndpointOptions{AllowPrivateTargets: true},
		Dialer:  net.Dialer{Timeout: 5 * time.Second},
		Authorize: func(*http.Request) bool {
			return true
		},
		RequestForParse: func(r *http.Request, _ *uritemplate.Template, _ bool) *http.Request {
			return r
		},
		RelaxAuthority: func(option.MasqueEndpointOptions, string) bool { return true },
	}
	mux.HandleFunc("/masque/ip", func(w http.ResponseWriter, r *http.Request) {
		_ = http.NewResponseController(w).EnableFullDuplex()
		server.HandleConnectIPRequest(host, w, r, ipTemplate)
	})

	tlsCfg := masque.InProcessH2TestTLS(tb)
	tlsLn := tls.NewListener(ln, tlsCfg)
	srv := &http.Server{Handler: mux}
	if err := http2.ConfigureServer(srv, mh2.BulkHTTP2ServerConfig()); err != nil {
		_ = ln.Close()
		return err
	}

	s.port = proxyPort
	s.tcpLn = ln
	s.srv = srv
	s.serveWG.Add(1)
	go func() {
		defer s.serveWG.Done()
		_ = srv.Serve(tlsLn)
	}()
	time.Sleep(20 * time.Millisecond)
	return nil
}

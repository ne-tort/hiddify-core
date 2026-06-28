package masque

// H2 CONNECT-stream in-process test harness (W-STR-4 PR6).

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	mh2 "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/sagernet/sing-box/transport/masque/session"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"golang.org/x/net/http2"
	"net/url"
)

const (
	h2ConnectStreamSocksPrefix     = "IPERFCOOK"
	h2ConnectStreamSocksBulkLen    = 48 * 1024
	h2ConnectStreamSocksMinRead    = h2ConnectStreamSocksBulkLen + len(h2ConnectStreamSocksPrefix)
	h2ConnectStreamSocksUploadGoal = 256 * 1024
	h2HonestGateMinBytes           = 32 * 1024
	h2HonestGateDuration           = 12 * time.Second
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func newConnectStreamH2ProdSession(t *testing.T, proxyPort int) (ClientSession, context.Context) {
	return newConnectStreamH2ProdSessionWithTCPDial(t, proxyPort, nil)
}

func newConnectStreamH2ProdSessionWithTCPDial(t *testing.T, proxyPort int, tcpDial func(context.Context, string, string) (net.Conn, error)) (ClientSession, context.Context) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	if tcpDial == nil {
		tcpDial = baseDial
	}
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(proxyPort),
		TransportMode:            option.MasqueTransportModeConnectUDP,
		TCPTransport:             option.MasqueTCPTransportConnectStream,
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
		MasqueQUICCryptoTLS:      &tls.Config{InsecureSkipVerify: true},
		TCPDial:                  tcpDial,
	})
	if err != nil {
		t.Fatalf("new connect-stream-h2 session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, waitCtx
}

func startH2ConnectStreamSocksRouter(t *testing.T, proxyPort int) uint16 {
	t.Helper()
	session, _ := newConnectStreamH2ProdSession(t, proxyPort)
	return startH2ConnectStreamSocksRouterWithSession(t, session)
}

func startH2ConnectStreamSocksRouterWithSession(t *testing.T, session ClientSession) uint16 {
	t.Helper()
	out := &masqueSessionOutbound{
		Adapter: outbound.NewAdapter(C.TypeMasque, "masque-out", []string{N.NetworkTCP, N.NetworkUDP}, nil),
		sess:    session,
	}
	cm := route.NewConnectionManager(log.StdLogger())
	t.Cleanup(func() { _ = cm.Close() })
	router := &directMasqueRouter{cm: cm, dialer: out}
	return startSocks5AssociateRelay(t, router, C.TypeSOCKS)
}

func socksTCPDial(t *testing.T, socksPort uint16, targetPort uint16) net.Conn {
	return socksTCPDialHost(t, socksPort, "127.0.0.1", targetPort)
}

func socksTCPDialHost(t *testing.T, socksPort uint16, targetHost string, targetPort uint16) net.Conn {
	t.Helper()
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", socksPort), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	conn, err := dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort(targetHost, targetPort))
	if err != nil {
		t.Fatalf("socks tcp dial %s:%d: %v", targetHost, targetPort, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func startH2DownloadFirstTarget(t *testing.T) (uint16, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen download target: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	prefix := h2ConnectStreamSocksPrefix
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				payload := make([]byte, h2ConnectStreamSocksBulkLen+len(prefix))
				copy(payload, prefix)
				for i := len(prefix); i < len(payload); i++ {
					payload[i] = 'D'
				}
				_, _ = conn.Write(payload)
			}(c)
		}
	}()
	return port, prefix
}

func startH2BannerUploadTarget(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upload target: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("iperf3\r\n"))
				_, _ = io.Copy(io.Discard, conn)
			}(c)
		}
	}()
	return port
}

func startH2FakeIperfDownloadTarget(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake iperf: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				if _, err := conn.Write([]byte("iperf3\r\n")); err != nil {
					return
				}
				buf := make([]byte, 4096)
				if _, err := conn.Read(buf); err != nil {
					return
				}
				go func() { _, _ = io.Copy(io.Discard, conn) }()
				payload := make([]byte, 64*1024)
				for i := range payload {
					payload[i] = 'B'
				}
				for i := 0; i < 4; i++ {
					if _, err := conn.Write(payload); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return port
}

// startH2FakeIperfStreamingDownloadTargetOn binds on all interfaces (docker live server tests).
func startH2FakeIperfStreamingDownloadTargetOn(t *testing.T, host string) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("listen fake iperf streaming on %s: %v", host, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				if _, err := conn.Write([]byte("iperf3\r\n")); err != nil {
					return
				}
				// Real iperf3 -R bulk leg: server streams download without waiting for params on this TCP.
				// Params arrive on a sibling CONNECT; consume any client blob in the background.
				go func() {
					buf := make([]byte, 4096)
					for {
						if _, err := conn.Read(buf); err != nil {
							return
						}
					}
				}()
				payload := make([]byte, 256*1024)
				for {
					if _, err := conn.Write(payload); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return port
}

// startH2FakeIperfStreamingDownloadTarget is iperf3 -R shape: banner, read client blob, stream bulk forever.
func startH2FakeIperfStreamingDownloadTarget(t *testing.T) uint16 {
	return startH2FakeIperfStreamingDownloadTargetOn(t, "127.0.0.1")
}

const iperf3CookieSize = 37

// testIperf3ClientCookie is a fixed 37-byte iperf3 control cookie (COOKIE_SIZE).
func testIperf3ClientCookie() []byte {
	return []byte("837af6e7010446d4bbf42b4b2e4e8ffd\x00\x00\x00\x00\x00")
}

// testIperf3ClientParamsJSON is a minimal reverse TCP params blob (real iperf3 upload-first shape).
func testIperf3ClientParamsJSON(cookie []byte) []byte {
	// Cookie in JSON is the printable prefix without trailing NUL padding.
	cookieStr := string(bytesTrimRight(cookie, 0))
	return []byte(`{"cookie":"` + cookieStr + `","tcp":true,"omit":0,"time":2,"parallel":1,"reverse":1,"bidir":0,"winband":0,"pacing_timer":0}`)
}

func bytesTrimRight(b []byte, cut byte) []byte {
	for len(b) > 0 && b[len(b)-1] == cut {
		b = b[:len(b)-1]
	}
	return b
}

// startRealIperf3UploadFirstTarget serves real iperf3 TCP control: read 37-byte cookie, consume params, bulk download.
func startRealIperf3UploadFirstTarget(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen real iperf3: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				cookie := make([]byte, iperf3CookieSize)
				if _, err := io.ReadFull(conn, cookie); err != nil {
					return
				}
				go func() {
					buf := make([]byte, 8*1024)
					for {
						if _, err := conn.Read(buf); err != nil {
							return
						}
					}
				}()
				payload := make([]byte, 64*1024)
				for i := range payload {
					payload[i] = 'B'
				}
				for i := 0; i < 4; i++ {
					if _, err := conn.Write(payload); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return port
}

// startH2FakeIperfConcurrentControlTarget serves iperf3 banner + bulk download while consuming
// periodic non-zero client upload (real iperf -R control path, not idle after params).
func startH2FakeIperfConcurrentControlTarget(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake iperf control: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				if _, err := conn.Write([]byte("iperf3\r\n")); err != nil {
					return
				}
				go func() {
					buf := make([]byte, 4096)
					for {
						if _, err := conn.Read(buf); err != nil {
							return
						}
					}
				}()
				payload := make([]byte, 64*1024)
				for i := range payload {
					payload[i] = 'B'
				}
				for {
					if _, err := conn.Write(payload); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return port
}
// startInProcessH2TCPConnectStreamProxy serves HTTPS + HTTP/2 Extended CONNECT-stream and relays TCP.
func startInProcessH2TCPConnectStreamProxy(tb testing.TB) int {
	tb.Helper()
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
		relayErr := strm.RelayTCPTunnel(r.Context(), target, r.Body, w, "")
		_ = target.Close()
		if relayErr != nil && relayErr != io.EOF {
			tb.Logf("relay finished: %v", relayErr)
		}
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen tcp: %v", err)
	}
	tlsLn := tls.NewListener(ln, serverTLS)
	srv := &http.Server{Handler: mux}
	if err := http2.ConfigureServer(srv, mh2.BulkHTTP2ServerConfig()); err != nil {
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
	return tlsLn.Addr().(*net.TCPAddr).Port
}
func dialH2ConnectStreamBenchTCPWindowed(tb testing.TB, proxyPort, targetPort int) net.Conn {
	tb.Helper()
	rawURL := "https://127.0.0.1:" + strconv.Itoa(proxyPort) + "/masque/tcp/127.0.0.1/" + strconv.Itoa(targetPort)
	tcpURL, err := url.Parse(rawURL)
	if err != nil {
		tb.Fatalf("parse url: %v", err)
	}

	s := newTestCoreSession(session.CoreSession{
		Options: ClientOptions{
			Server:              "127.0.0.1",
			ServerPort:          uint16(proxyPort),
			MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
			TCPTransport:        option.MasqueTCPTransportConnectStream,
		},
	})
	link := benchWindowedBidiLinkStrict()
	s.Options.TCPDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return link.wrap(conn), nil
	}
	s.UDPHTTPLayer.Store(option.MasqueHTTPLayerH2)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	tb.Cleanup(cancel)

	conn, err := s.dialTCPStreamH2(ctx, tcpURL, s.Options, "127.0.0.1", M.ParseSocksaddrHostPort("127.0.0.1", uint16(targetPort)))
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}
	tb.Cleanup(func() { _ = conn.Close() })
	return conn
}

// runH2HonestGateDuplexWriteTo runs WriteTo download with concurrent upload control pulses
// (docker iperf -R shape: download-first WriteTo + non-zero upload leg).
func runH2HonestGateDuplexWriteTo(t *testing.T, conn net.Conn, duration time.Duration, minBytes int64) int64 {
	t.Helper()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		control := make([]byte, 64)
		for i := range control {
			control[i] = 'C'
		}
		ticker := time.NewTicker(30 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if _, err := conn.Write(control); err != nil {
					return
				}
			}
		}
	}()

	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, _, err := measureTCPDownloadWriteToMbps(conn, duration)
		done <- result{n: n, err: err}
	}()

	select {
	case r := <-done:
		if r.err != nil && r.n == 0 {
			t.Fatalf("honest gate WriteTo: %v", r.err)
		}
		return r.n
	case <-time.After(duration + 5*time.Second):
		t.Fatal("honest gate WriteTo blocked past deadline (H2 bidi FC stall)")
		return 0
	}
}

func startH2ConnectStreamDownloadTarget(tb testing.TB) uint16 {
	tb.Helper()
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen download target: %v", err)
	}
	tb.Cleanup(func() { _ = targetLn.Close() })
	port := uint16(targetLn.Addr().(*net.TCPAddr).Port)
	buf := make([]byte, 256*1024)
	go func() {
		for {
			c, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				go func() { _, _ = io.Copy(io.Discard, c) }()
				deadline := time.Now().Add(30 * time.Second)
				for time.Now().Before(deadline) {
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return port
}

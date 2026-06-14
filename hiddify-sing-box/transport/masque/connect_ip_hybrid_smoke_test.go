package masque_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque/server"
	"github.com/sagernet/sing-box/transport/masque"
	mh2 "github.com/sagernet/sing-box/transport/masque/h2"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

const (
	connectIPHybridSmokeEchoPayload = "hybrid-smoke"
	connectIPHybridSmokeMinDownMbps   = 1.0  // functional smoke only
	connectIPHybridSmokeMinBytes      = 4096
	connectIPHybridSmokeBenchDur      = 200 * time.Millisecond
	connectIPHybridSynthBenchDur      = 2 * time.Second // GATE connect-ip-h2 TCP leg
)

func startHybridConnectIPH3Server(tb testing.TB) int {
	tb.Helper()
	tlsCfg := masque.InProcessH3TestTLS(tb)
	quicConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		tb.Fatalf("listen quic udp: %v", err)
	}
	proxyPort := quicConn.LocalAddr().(*net.UDPAddr).Port

	mux := http.NewServeMux()
	ipTemplateRaw := fmt.Sprintf("https://127.0.0.1:%d/masque/ip", proxyPort)
	ipTemplate, err := uritemplate.New(ipTemplateRaw)
	if err != nil {
		tb.Fatalf("ip template: %v", err)
	}
	host := server.ConnectIPHandlerHost{
		Tag:     "hybrid-smoke",
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
		server.HandleConnectIPRequest(host, w, r, ipTemplate)
	})
	tcpTemplate := uritemplate.MustNew(fmt.Sprintf("https://127.0.0.1:%d/masque/tcp/{target_host}/{target_port}", proxyPort))
	mux.HandleFunc("/masque/tcp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		tcpHost := server.TCPConnectHost{
			Options: option.MasqueEndpointOptions{AllowPrivateTargets: true},
			Dialer:  net.Dialer{Timeout: 5 * time.Second},
			Authorize: func(*http.Request) bool {
				return true
			},
			AuthorityMatches: func(_, _ string, _ bool) bool { return true },
		}
		server.HandleTCPConnectRequest(tcpHost, w, r, tcpTemplate, true)
	})

	srv := http3.Server{
		TLSConfig:       tlsCfg,
		QUICConfig:      masque.MasqueHTTPServerQUICConfig(),
		EnableDatagrams: true,
		Handler:         mux,
	}
	var serveWG sync.WaitGroup
	serveWG.Add(1)
	go func() {
		defer serveWG.Done()
		_ = srv.Serve(quicConn)
	}()
	tb.Cleanup(func() {
		_ = srv.Close()
		serveWG.Wait()
		_ = quicConn.Close()
	})
	time.Sleep(20 * time.Millisecond)
	return proxyPort
}

func startHybridConnectIPH2Server(tb testing.TB) int {
	tb.Helper()
	serverTLS := masque.InProcessH3TestTLS(tb)
	serverTLS.NextProtos = []string{http2.NextProtoTLS, "http/1.1"}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen tcp: %v", err)
	}
	proxyPort := ln.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()
	ipTemplateRaw := fmt.Sprintf("https://127.0.0.1:%d/masque/ip", proxyPort)
	ipTemplate, err := uritemplate.New(ipTemplateRaw)
	if err != nil {
		tb.Fatalf("ip template: %v", err)
	}
	ipHost := server.ConnectIPHandlerHost{
		Tag:     "hybrid-smoke-h2",
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
		server.HandleConnectIPRequest(ipHost, w, r, ipTemplate)
	})
	tcpTemplate := uritemplate.MustNew(fmt.Sprintf("https://127.0.0.1:%d/masque/tcp/{target_host}/{target_port}", proxyPort))
	mux.HandleFunc("/masque/tcp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if p := r.Header.Get(":protocol"); p != "" && p != strm.H2ConnectStreamProto {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		tcpHost := server.TCPConnectHost{
			Options: option.MasqueEndpointOptions{AllowPrivateTargets: true},
			Dialer:  net.Dialer{Timeout: 5 * time.Second},
			Authorize: func(*http.Request) bool {
				return true
			},
			AuthorityMatches: func(_, _ string, _ bool) bool { return true },
		}
		server.HandleTCPConnectRequest(tcpHost, w, r, tcpTemplate, true)
	})

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
	return proxyPort
}

func startHybridConnectIPEchoTarget(tb testing.TB) net.Listener {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("echo listen: %v", err)
	}
	tb.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln
}

func startHybridConnectIPDownloadTarget(tb testing.TB) net.Listener {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("download listen: %v", err)
	}
	tb.Cleanup(func() { _ = ln.Close() })
	buf := make([]byte, 256*1024)
	go func() {
		for {
			c, err := ln.Accept()
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
	return ln
}

type hybridSmokeBenchSink struct {
	deadline time.Time
	total    int64
}

func (s *hybridSmokeBenchSink) Write(p []byte) (int, error) {
	if time.Now().After(s.deadline) {
		return 0, io.EOF
	}
	s.total += int64(len(p))
	return len(p), nil
}

func measureHybridSmokeDownloadWriteToMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	wt, ok := conn.(io.WriterTo)
	if !ok {
		return 0, 0, fmt.Errorf("masque: conn lacks io.WriterTo")
	}
	deadline := time.Now().Add(duration)
	_ = conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})
	sink := &hybridSmokeBenchSink{deadline: deadline}
	_, err := wt.WriteTo(sink)
	if err != nil && err != io.EOF && sink.total == 0 {
		return 0, 0, err
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return sink.total, float64(sink.total*8) / secs / 1e6, nil
}

// TestConnectIPHybridConnectStreamH3Smoke exercises prod connect-ip-h3 hybrid profile in-proc:
// transport_mode=connect_ip (OpenIPSession) + tcp_transport=connect_stream (DialContext TCP leg).
func TestConnectIPHybridConnectStreamH3Smoke(t *testing.T) {
	echoLn := startHybridConnectIPEchoTarget(t)
	downLn := startHybridConnectIPDownloadTarget(t)
	proxyPort := startHybridConnectIPH3Server(t)

	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session, err := (masque.CoreClientFactory{}).NewSession(waitCtx, masque.ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TransportMode:       "connect_ip",
		TCPTransport:        "connect_stream",
	})
	if err != nil {
		t.Fatalf("new hybrid session: %v", err)
	}
	defer session.Close()

	caps := session.Capabilities()
	if !caps.ConnectIP {
		t.Fatal("expected ConnectIP capability on hybrid session")
	}
	if !caps.ConnectTCP {
		t.Fatal("expected ConnectTCP capability on hybrid connect_ip+connect_stream session")
	}

	ipSess, err := session.OpenIPSession(waitCtx)
	if err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}
	if ipSess == nil {
		t.Fatal("expected non-nil CONNECT-IP packet session")
	}

	echoPort := uint16(echoLn.Addr().(*net.TCPAddr).Port)
	echoConn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", echoPort))
	if err != nil {
		t.Fatalf("DialContext tcp (connect_stream leg): %v", err)
	}
	defer echoConn.Close()

	payload := []byte(connectIPHybridSmokeEchoPayload)
	if _, err := echoConn.Write(payload); err != nil {
		t.Fatalf("write echo: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(echoConn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("DialContext download: %v", err)
	}
	defer downConn.Close()

	n, mbps, err := measureHybridSmokeDownloadWriteToMbps(downConn, connectIPHybridSmokeBenchDur)
	if err != nil {
		t.Fatalf("download WriteTo: %v", err)
	}
	t.Logf("connect-ip-h3 hybrid download sanity: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < connectIPHybridSmokeMinDownMbps && n < connectIPHybridSmokeMinBytes {
		t.Fatalf("hybrid download too slow: %.1f Mbit/s %d bytes (want >= %.0f Mbit/s or >= %d bytes)",
			mbps, n, connectIPHybridSmokeMinDownMbps, connectIPHybridSmokeMinBytes)
	}
}

// TestConnectIPHybridConnectStreamH2Smoke exercises prod connect-ip-h2 hybrid profile in-proc:
// transport_mode=connect_ip (OpenIPSession) + tcp_transport=connect_stream over HTTP/2.
func TestConnectIPHybridConnectStreamH2Smoke(t *testing.T) {
	echoLn := startHybridConnectIPEchoTarget(t)
	downLn := startHybridConnectIPDownloadTarget(t)
	proxyPort := startHybridConnectIPH2Server(t)

	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	session, err := (masque.CoreClientFactory{}).NewSession(waitCtx, masque.ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(proxyPort),
		MasqueQUICCryptoTLS:      &tls.Config{InsecureSkipVerify: true},
		TransportMode:            "connect_ip",
		TCPTransport:             "connect_stream",
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
		TCPDial:                  baseDial,
	})
	if err != nil {
		t.Fatalf("new hybrid h2 session: %v", err)
	}
	defer session.Close()

	caps := session.Capabilities()
	if !caps.ConnectIP {
		t.Fatal("expected ConnectIP capability on hybrid h2 session")
	}
	if !caps.ConnectTCP {
		t.Fatal("expected ConnectTCP capability on hybrid connect_ip+connect_stream h2 session")
	}

	ipSess, err := session.OpenIPSession(waitCtx)
	if err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}
	if ipSess == nil {
		t.Fatal("expected non-nil CONNECT-IP packet session on h2")
	}

	echoPort := uint16(echoLn.Addr().(*net.TCPAddr).Port)
	echoConn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", echoPort))
	if err != nil {
		t.Fatalf("DialContext tcp (connect_stream h2 leg): %v", err)
	}
	defer echoConn.Close()

	payload := []byte(connectIPHybridSmokeEchoPayload)
	if _, err := echoConn.Write(payload); err != nil {
		t.Fatalf("write echo: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(echoConn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("DialContext download: %v", err)
	}
	defer downConn.Close()

	n, mbps, err := measureHybridSmokeDownloadWriteToMbps(downConn, connectIPHybridSmokeBenchDur)
	if err != nil {
		t.Fatalf("download WriteTo: %v", err)
	}
	t.Logf("connect-ip-h2 hybrid download sanity: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < connectIPHybridSmokeMinDownMbps && n < connectIPHybridSmokeMinBytes {
		t.Fatalf("hybrid h2 download too slow: %.1f Mbit/s %d bytes (want >= %.0f Mbit/s or >= %d bytes)",
			mbps, n, connectIPHybridSmokeMinDownMbps, connectIPHybridSmokeMinBytes)
	}
}

// TestConnectIPHybridConnectStreamH2DownloadKPI (GATE connect-ip-h2 TCP leg) — connect_ip + connect_stream H2
// download WriteTo must reach synth prod floor (same class as connect-stream-h2).
func TestConnectIPHybridConnectStreamH2DownloadKPI(t *testing.T) {
	downLn := startHybridConnectIPDownloadTarget(t)
	proxyPort := startHybridConnectIPH2Server(t)

	waitCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	session, err := (masque.CoreClientFactory{}).NewSession(waitCtx, masque.ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(proxyPort),
		MasqueQUICCryptoTLS:      &tls.Config{InsecureSkipVerify: true},
		TransportMode:            "connect_ip",
		TCPTransport:             "connect_stream",
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
		TCPDial:                  baseDial,
	})
	if err != nil {
		t.Fatalf("new hybrid h2 session: %v", err)
	}
	defer session.Close()

	if _, err := session.OpenIPSession(waitCtx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("DialContext download: %v", err)
	}
	defer downConn.Close()

	n, mbps, err := measureHybridSmokeDownloadWriteToMbps(downConn, connectIPHybridSynthBenchDur)
	if err != nil && n == 0 {
		t.Fatalf("connect-ip-h2 download WriteTo: %v", err)
	}
	t.Logf("connect-ip-h2 hybrid download KPI: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < masque.ExportConnectStreamSynthProdMinMbps {
		t.Fatalf("%s", masque.ExportSynthKPIDiagnostic("[connect-ip-h2 L3 hybrid]", "tcp_down WriteTo", mbps,
			masque.ExportConnectStreamSynthProdMinMbps,
			"connect_ip packet plane + H2 connect_stream TCP leg"))
	}
}

// TestConnectIPHybridConnectStreamH3DownloadKPI (GATE connect-ip-h3 TCP leg) — parity target for H3 hybrid.
func TestConnectIPHybridConnectStreamH3DownloadKPI(t *testing.T) {
	downLn := startHybridConnectIPDownloadTarget(t)
	proxyPort := startHybridConnectIPH3Server(t)

	waitCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	session, err := (masque.CoreClientFactory{}).NewSession(waitCtx, masque.ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TransportMode:       "connect_ip",
		TCPTransport:        "connect_stream",
	})
	if err != nil {
		t.Fatalf("new hybrid h3 session: %v", err)
	}
	defer session.Close()

	if _, err := session.OpenIPSession(waitCtx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("DialContext download: %v", err)
	}
	defer downConn.Close()

	n, mbps, err := measureHybridSmokeDownloadWriteToMbps(downConn, connectIPHybridSynthBenchDur)
	if err != nil && n == 0 {
		t.Fatalf("connect-ip-h3 download WriteTo: %v", err)
	}
	t.Logf("connect-ip-h3 hybrid download KPI: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < masque.ExportConnectStreamSynthProdMinMbps {
		t.Fatalf("%s", masque.ExportSynthKPIDiagnostic("[connect-ip-h3 L3 hybrid]", "tcp_down WriteTo", mbps,
			masque.ExportConnectStreamSynthProdMinMbps,
			"connect_ip packet plane + H3 connect_stream TCP leg"))
	}
}

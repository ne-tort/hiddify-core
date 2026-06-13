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
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

const (
	connectIPHybridSmokeEchoPayload = "hybrid-smoke"
	connectIPHybridSmokeMinDownMbps = 1.0
	connectIPHybridSmokeMinBytes    = 4096
	connectIPHybridSmokeBenchDur    = 200 * time.Millisecond
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

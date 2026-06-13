package masque_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque/server"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/yosida95/uritemplate/v3"
)

const (
	e2eBenchDuration       = 400 * time.Millisecond
	e2eVPSKPITargetDownMbps = 21.0
	e2eLocalizeFastMbps     = 80.0
)

var e2eConnectTemplate = uritemplate.MustNew("https://masque.local/masque/tcp/{target_host}/{target_port}")

func e2eProdServerHandler(_targetHost, _targetPort string, r *http.Request, w http.ResponseWriter) {
	host := server.TCPConnectHost{
		Options: option.MasqueEndpointOptions{AllowPrivateTargets: true},
		Dialer:  net.Dialer{Timeout: 5 * time.Second},
		Authorize: func(*http.Request) bool {
			return true
		},
		AuthorityMatches: func(_, _ string, _ bool) bool { return true },
	}
	server.HandleTCPConnectRequest(host, w, r, e2eConnectTemplate, true)
}

func startE2ETCPConnectProxy(tb testing.TB, tlsCfg *tls.Config, handler func(string, string, *http.Request, http.ResponseWriter)) int {
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

func startE2EDownloadTarget(tb testing.TB) net.Listener {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("target listen: %v", err)
	}
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
	tb.Cleanup(func() { _ = ln.Close() })
	return ln
}

var errE2EBenchElapsed = &e2eBenchElapsedErr{}

type e2eBenchWriteToSink struct {
	deadline time.Time
	total    int64
}

func (s *e2eBenchWriteToSink) Write(p []byte) (int, error) {
	if time.Now().After(s.deadline) {
		return 0, errE2EBenchElapsed
	}
	s.total += int64(len(p))
	return len(p), nil
}

type e2eBenchElapsedErr struct{}

func (e *e2eBenchElapsedErr) Error() string { return "masque: e2e bench duration elapsed" }

func measureE2EDownloadWriteToMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	wt, ok := conn.(io.WriterTo)
	if !ok {
		return 0, 0, io.ErrUnexpectedEOF
	}
	deadline := time.Now().Add(duration)
	_ = conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})
	sink := &e2eBenchWriteToSink{deadline: deadline}
	_, err := wt.WriteTo(sink)
	if err != nil && err != errE2EBenchElapsed && err != io.EOF && sink.total == 0 {
		return 0, 0, err
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return sink.total, float64(sink.total*8) / secs / 1e6, nil
}

// TestArchE2EConnectStreamL3WriteTo (REF4-2): sb client → HandleTCPConnectRequest → target, instant wire >21.
func TestArchE2EConnectStreamL3WriteTo(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_STREAM_PIPE_UPLOAD", "0")
	t.Setenv("MASQUE_CONNECT_STREAM_DUAL_CONNECT", "0")
	t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "0")
	t.Setenv("MASQUE_RELAY_TCP_LEGACY", "")

	runArchE2EConnectStreamL3WriteToBench(t, "REF4-2 E2E sb client → sb server handler → target")
}

// TestArchE2EConnectStreamL3WriteToProdHijack (REF4-2b): prod default STREAM_HIJACK=1 on real QUIC stack.
func TestArchE2EConnectStreamL3WriteToProdHijack(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_STREAM_PIPE_UPLOAD", "0")
	t.Setenv("MASQUE_CONNECT_STREAM_DUAL_CONNECT", "0")
	t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "1")
	t.Setenv("MASQUE_RELAY_TCP_LEGACY", "")

	runArchE2EConnectStreamL3WriteToBench(t, "REF4-2b E2E prod hijack sb client → sb server → target")
}

func runArchE2EConnectStreamL3WriteToBench(t *testing.T, logPrefix string) {
	t.Helper()
	tlsCfg := masque.InProcessH3TestTLS(t)
	targetLn := startE2EDownloadTarget(t)
	proxyPort := startE2ETCPConnectProxy(t, tlsCfg, e2eProdServerHandler)

	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	session, err := (masque.CoreClientFactory{}).NewSession(waitCtx, masque.ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TCPTransport:        "connect_stream",
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer session.Close()

	targetPort := uint16(targetLn.Addr().(*net.TCPAddr).Port)
	conn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", targetPort))
	if err != nil {
		t.Fatalf("dial connect-stream: %v", err)
	}
	defer conn.Close()

	n, mbps, err := measureE2EDownloadWriteToMbps(conn, e2eBenchDuration)
	if err != nil {
		t.Fatalf("E2E WriteTo: %v", err)
	}
	t.Logf("%s: %.1f Mbit/s (%d bytes)", logPrefix, mbps, n)
	if mbps <= e2eVPSKPITargetDownMbps {
		t.Fatalf("E2E instant download %.1f Mbit/s (want > %.0f REF4-2 KPI)", mbps, e2eVPSKPITargetDownMbps)
	}
	if mbps < e2eLocalizeFastMbps {
		t.Fatalf("E2E instant download slow: %.1f Mbit/s (want >= %.0f in-proc fast band)", mbps, e2eLocalizeFastMbps)
	}
}

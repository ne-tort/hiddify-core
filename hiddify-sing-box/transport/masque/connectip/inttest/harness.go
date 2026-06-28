package inttest

// In-process CONNECT-IP hybrid harness (W-IP-0 PR1). Imports protocol/server here to avoid
// masque ↔ server import cycle when external tests import transport/masque.

import (
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
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

const (
	HybridSmokeEchoPayload = "hybrid-smoke"
	HybridSmokeMinDownMbps = 1.0
	HybridSmokeMinBytes    = 4096
	HybridSmokeBenchDur    = 200 * time.Millisecond
	HybridSynthBenchDur    = 2 * time.Second
	// HybridNativeProfileLocalIPv4 matches generic-server AssignAddresses (198.18.0.1/32).
	HybridNativeProfileLocalIPv4 = "198.18.0.1"
)

// HybridNativeH3ClientOptions builds ClientOptions for native connect_ip TCP leg on hybrid H3 server.
func HybridNativeH3ClientOptions(proxyPort int) masque.ClientOptions {
	return masque.ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TransportMode:       "connect_ip",
		TCPTransport:        "connect_ip",
		ProfileLocalIPv4:    HybridNativeProfileLocalIPv4,
	}
}

// HybridConnectStreamH3ClientOptions builds ClientOptions for connect_ip + connect_stream over H3.
func HybridConnectStreamH3ClientOptions(proxyPort int) masque.ClientOptions {
	return masque.ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TransportMode:       "connect_ip",
		TCPTransport:        "connect_stream",
		ProfileLocalIPv4:    HybridNativeProfileLocalIPv4,
	}
}

// HybridConnectStreamH2ClientOptions builds ClientOptions for connect_ip + connect_stream over H2.
func HybridConnectStreamH2ClientOptions(proxyPort int, tcpDial masque.MasqueTCPDialFunc) masque.ClientOptions {
	return masque.ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(proxyPort),
		MasqueQUICCryptoTLS:      &tls.Config{InsecureSkipVerify: true},
		TransportMode:            "connect_ip",
		TCPTransport:             "connect_stream",
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
		TCPDial:                  tcpDial,
	}
}

func StartHybridConnectIPH3Server(tb testing.TB) int {
	tb.Helper()
	return NewHybridConnectIPH3Server(tb).Port()
}

// HybridConnectIPH3Server is a restartable in-proc CONNECT-IP H3 server (W-IP-TUN synth).
type HybridConnectIPH3Server struct {
	port    int
	quicLn  *net.UDPConn
	h3srv   *http3.Server
	serveWG sync.WaitGroup
}

// NewHybridConnectIPH3Server starts an H3 CONNECT-IP server; tb.Cleanup stops it.
func NewHybridConnectIPH3Server(tb testing.TB) *HybridConnectIPH3Server {
	tb.Helper()
	s := &HybridConnectIPH3Server{}
	if err := s.launch(tb, 0); err != nil {
		tb.Fatalf("launch h3 server: %v", err)
	}
	tb.Cleanup(func() { _ = s.Stop() })
	return s
}

func (s *HybridConnectIPH3Server) Port() int { return s.port }

func (s *HybridConnectIPH3Server) Stop() error {
	if s.h3srv != nil {
		_ = s.h3srv.Close()
	}
	s.serveWG.Wait()
	if s.quicLn != nil {
		_ = s.quicLn.Close()
		s.quicLn = nil
	}
	s.h3srv = nil
	return nil
}

// Restart stops and relaunches the server on the same UDP port (Docker masque-server-core parity).
func (s *HybridConnectIPH3Server) Restart(tb testing.TB) {
	tb.Helper()
	keepPort := s.port
	_ = s.Stop()
	time.Sleep(50 * time.Millisecond)
	if err := s.launch(tb, keepPort); err != nil {
		tb.Fatalf("restart h3 server: %v", err)
	}
}

func (s *HybridConnectIPH3Server) launch(tb testing.TB, fixedPort int) error {
	tlsCfg := masque.InProcessH3TestTLS(tb)
	quicConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: fixedPort})
	if err != nil {
		return err
	}
	proxyPort := quicConn.LocalAddr().(*net.UDPAddr).Port

	mux := http.NewServeMux()
	ipTemplateRaw := fmt.Sprintf("https://127.0.0.1:%d/masque/ip", proxyPort)
	ipTemplate, err := uritemplate.New(ipTemplateRaw)
	if err != nil {
		_ = quicConn.Close()
		return err
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

	s.port = proxyPort
	s.quicLn = quicConn
	s.h3srv = &http3.Server{
		TLSConfig:       tlsCfg,
		QUICConfig:      masque.MasqueHTTPServerQUICConfig(),
		EnableDatagrams: true,
		Handler:         mux,
	}
	s.serveWG.Add(1)
	go func() {
		defer s.serveWG.Done()
		_ = s.h3srv.Serve(quicConn)
	}()
	time.Sleep(20 * time.Millisecond)
	return nil
}

func StartHybridConnectIPH2Server(tb testing.TB) int {
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
		_ = http.NewResponseController(w).EnableFullDuplex()
		server.HandleConnectIPRequest(ipHost, w, r, ipTemplate)
	})
	tcpTemplate := uritemplate.MustNew(fmt.Sprintf("https://127.0.0.1:%d/masque/tcp/{target_host}/{target_port}", proxyPort))
	mux.HandleFunc("/masque/tcp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if p := r.Header.Get(":protocol"); p != "" && p != "HTTP/2" {
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

func StartHybridConnectIPEchoTarget(tb testing.TB) net.Listener {
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

// StartHybridConnectIPIperfReverseTarget serves iperf3 -R setup: read 89B params, write 53B header, then bulk.
func StartHybridConnectIPIperfReverseTarget(tb testing.TB) net.Listener {
	tb.Helper()
	return startHybridConnectIPIperfReverseTarget(tb, true)
}

// StartHybridConnectIPIperfReverseHeaderOnlyTarget is synth localization: 53B header only, no bulk flood.
func StartHybridConnectIPIperfReverseHeaderOnlyTarget(tb testing.TB) net.Listener {
	tb.Helper()
	return startHybridConnectIPIperfReverseTarget(tb, false)
}

func startHybridConnectIPIperfReverseTarget(tb testing.TB, withBulk bool) net.Listener {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("iperf-reverse listen: %v", err)
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
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.SetNoDelay(true)
				}
				params := make([]byte, 89)
				if _, err := io.ReadFull(c, params); err != nil {
					return
				}
				reply := make([]byte, 53)
				reply[0] = 0x49
				if _, err := c.Write(reply); err != nil {
					return
				}
				if !withBulk {
					_, _ = io.Copy(io.Discard, c)
					return
				}
				// Let client enter ReadFull on header before bulk floods hybrid forwarder/pump.
				time.Sleep(50 * time.Millisecond)
				chunk := make([]byte, 16*1024)
				deadline := time.Now().Add(30 * time.Second)
				for time.Now().Before(deadline) {
					if _, err := c.Write(chunk); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln
}

// StartHybridConnectIPSingleChunkDownloadTarget sends one chunk after client probe (kernel bulk localize).
func StartHybridConnectIPSingleChunkDownloadTarget(tb testing.TB, chunkLen int) net.Listener {
	tb.Helper()
	if chunkLen <= 0 {
		chunkLen = 4096
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("single-chunk download listen: %v", err)
	}
	tb.Cleanup(func() { _ = ln.Close() })
	chunk := make([]byte, chunkLen)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.SetNoDelay(true)
				}
				probe := make([]byte, 1)
				if _, err := io.ReadFull(c, probe); err != nil {
					return
				}
				if _, err := c.Write(chunk); err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln
}

func StartHybridConnectIPDownloadTarget(tb testing.TB) net.Listener {
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
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.SetNoDelay(true)
				}
				// Wait for client payload before bulk (forwarder S2C requires clientPayloadSeen).
				probe := make([]byte, 1)
				if _, err := io.ReadFull(c, probe); err != nil {
					return
				}
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

func MeasureHybridSmokeDownloadWriteToMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	wt, ok := conn.(io.WriterTo)
	if !ok {
		return 0, 0, fmt.Errorf("masque: conn lacks io.WriterTo")
	}
	// Download target waits for one client byte before bulk (forwarder clientPayloadSeen parity).
	if _, err := conn.Write([]byte{0x42}); err != nil {
		return 0, 0, err
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

package masque

// In-process SOCKS5 TCP CONNECT → masque connect_stream (H2) → bulk TCP target.
// Exercises route.ConnectionManager writer_to/reader_from path (docker connect-stream-h2 shape).

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

const (
	h2ConnectStreamSocksPrefix     = "IPERFCOOK"
	h2ConnectStreamSocksBulkLen    = 48 * 1024
	h2ConnectStreamSocksMinRead    = h2ConnectStreamSocksBulkLen + len(h2ConnectStreamSocksPrefix)
	h2ConnectStreamSocksUploadGoal = 256 * 1024
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

// TestH2ConnectStreamSocksDownloadFirstSmoke routes SOCKS5 TCP through H2 CONNECT-stream
// download-first (writer_to) — docker connect-stream-h2 tcp_down shape.
func TestH2ConnectStreamSocksDownloadFirstSmoke(t *testing.T) {
	targetPort, wantPrefix := startH2DownloadFirstTarget(t)
	proxyPort := startInProcessH2TCPConnectStreamProxy(t)
	socksPort := startH2ConnectStreamSocksRouter(t, proxyPort)

	conn := socksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	// iperf -R keeps a small upload leg active while download runs (H2 bidi FC).
	go func() {
		tick := make([]byte, 4096)
		deadline := time.Now().Add(6 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := conn.Write(tick); err != nil {
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
	}()

	var dst bytes.Buffer
	n, err := io.Copy(&dst, conn)
	if err != nil && n == 0 {
		t.Fatalf("read download: %v", err)
	}
	if n < int64(len(wantPrefix)) {
		t.Fatalf("download too short for prefix: %d", n)
	}
	got := dst.String()
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("download prefix lost: got %q want prefix %q", got[:min(len(got), len(wantPrefix)+4)], wantPrefix)
	}
	if n < int64(h2ConnectStreamSocksMinRead) {
		t.Fatalf("short download: %d want >= %d", n, h2ConnectStreamSocksMinRead)
	}
}

// TestH2ConnectStreamSocksDownloadNoUploadPulse routes SOCKS5 download-first without synthetic
// upload ticks — docker iperf -R shape (no client-side upload pulse goroutine).
func TestH2ConnectStreamSocksDownloadNoUploadPulse(t *testing.T) {
	targetPort, wantPrefix := startH2DownloadFirstTarget(t)
	proxyPort := startInProcessH2TCPConnectStreamProxy(t)
	socksPort := startH2ConnectStreamSocksRouter(t, proxyPort)

	conn := socksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	var dst bytes.Buffer
	n, err := io.Copy(&dst, conn)
	if err != nil && n == 0 {
		t.Fatalf("read download without upload pulse: %v", err)
	}
	if n < int64(len(wantPrefix)) {
		t.Fatalf("download too short for prefix: %d", n)
	}
	got := dst.String()
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("download prefix lost: got %q want prefix %q", got[:min(len(got), len(wantPrefix)+4)], wantPrefix)
	}
	if n < int64(h2ConnectStreamSocksMinRead) {
		t.Fatalf("short download: %d want >= %d", n, h2ConnectStreamSocksMinRead)
	}
}

// TestH2ConnectStreamSocksFakeIperfDownloadNoPulse reproduces docker iperf -R handshake:
// server banner → client params → bulk download, without synthetic upload pulse.
func TestH2ConnectStreamSocksFakeIperfDownloadNoPulse(t *testing.T) {
	targetPort := startH2FakeIperfDownloadTarget(t)
	proxyPort := startInProcessH2TCPConnectStreamProxy(t)
	socksPort := startH2ConnectStreamSocksRouter(t, proxyPort)

	conn := socksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	// iperf3 -R client shape on the SOCKS TCP socket (ConnectionManager reader_from /
	// writer_to run concurrently on the masque leg).
	banner := make([]byte, 8)
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("read fake iperf banner: %v", err)
	}
	if string(banner) != "iperf3\r\n" {
		t.Fatalf("banner: got %q", string(banner))
	}
	if _, err := conn.Write([]byte("FAKEIPERF")); err != nil {
		t.Fatalf("write fake iperf params: %v", err)
	}

	var dst bytes.Buffer
	n, err := io.Copy(&dst, conn)
	if err != nil && n == 0 {
		t.Fatalf("fake iperf download: %v", err)
	}
	if n < 32*1024 {
		t.Fatalf("fake iperf download short: %d want >= 32KiB", n)
	}
	if !strings.HasPrefix(dst.String(), "BBBB") {
		t.Fatalf("fake iperf bulk prefix lost: got %q", dst.String()[:min(len(dst.String()), 16)])
	}
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

// TestH2ConnectStreamConnectionManagerDuplex exercises route.ConnectionManager writer_to +
// reader_from on fake iperf -R handshake without synthetic upload pulse.
func TestH2ConnectStreamConnectionManagerDuplex(t *testing.T) {
	TestH2ConnectStreamSocksFakeIperfDownloadNoPulse(t)
}

// TestH2ConnectStreamSocksUploadBannerSmoke routes SOCKS5 TCP upload (reader_from) when the
// onward server sends an iperf banner without a concurrent client read.
func TestH2ConnectStreamSocksUploadBannerSmoke(t *testing.T) {
	targetPort := startH2BannerUploadTarget(t)
	proxyPort := startInProcessH2TCPConnectStreamProxy(t)
	socksPort := startH2ConnectStreamSocksRouter(t, proxyPort)

	conn := socksTCPDial(t, socksPort, targetPort)
	uploadDone := make(chan error, 1)
	go func() {
		payload := make([]byte, 32*1024)
		total := 0
		deadline := time.Now().Add(4 * time.Second)
		for total < h2ConnectStreamSocksUploadGoal && time.Now().Before(deadline) {
			n, err := conn.Write(payload)
			total += n
			if err != nil {
				uploadDone <- err
				return
			}
		}
		uploadDone <- nil
	}()

	select {
	case err := <-uploadDone:
		if err != nil {
			t.Fatalf("upload via SOCKS: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SOCKS upload blocked >5s with server banner (H2 drain expected)")
	}
}

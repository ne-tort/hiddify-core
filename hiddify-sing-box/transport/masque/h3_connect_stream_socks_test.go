package masque

// In-process SOCKS5 TCP CONNECT → masque connect_stream (H3) → bulk TCP target.

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	N "github.com/sagernet/sing/common/network"
)

func newConnectStreamH3ProdSession(t *testing.T, proxyPort int) (ClientSession, context.Context) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(proxyPort),
		TransportMode:            option.MasqueTransportModeConnectUDP,
		TCPTransport:             option.MasqueTCPTransportConnectStream,
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
		MasqueQUICCryptoTLS:      &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("new connect-stream-h3 session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, waitCtx
}

func newConnectStreamH3DockerLiveSession(t *testing.T) ClientSession {
	t.Helper()
	if os.Getenv("DOCKER_LIVE_SERVER") != "1" {
		t.Skip("set DOCKER_LIVE_SERVER=1 with masque-perf-lab up")
	}
	host := strings.TrimSpace(os.Getenv("DOCKER_MASQUE_SERVER"))
	if host == "" {
		host = "masque-server-core"
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:                   host,
		ServerPort:               8443,
		TransportMode:            option.MasqueTransportModeConnectUDP,
		TCPTransport:             option.MasqueTCPTransportConnectStream,
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
		MasqueQUICCryptoTLS:      &tls.Config{ServerName: host, InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("docker live connect-stream-h3 session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func startH3ConnectStreamSocksRouter(t *testing.T, proxyPort int) uint16 {
	t.Helper()
	session, _ := newConnectStreamH3ProdSession(t, proxyPort)
	return startH3ConnectStreamSocksRouterWithSession(t, session)
}

func startH3ConnectStreamSocksRouterWithSession(t *testing.T, session ClientSession) uint16 {
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

func runH3SocksFakeIperfNoPulse(t *testing.T, proxyPort int, targetPort uint16, minBytes int64) int64 {
	t.Helper()
	socksPort := startH3ConnectStreamSocksRouter(t, proxyPort)
	conn := socksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

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
	if n < minBytes {
		t.Fatalf("fake iperf download short: %d want >= %d", n, minBytes)
	}
	if !strings.HasPrefix(dst.String(), "BBBB") {
		t.Fatalf("fake iperf bulk prefix lost: got %q", dst.String()[:min(len(dst.String()), 16)])
	}
	return n
}

// TestH3FakeIperfParamsReachTarget probes whether iperf -R params reach onward TCP
// (isolates upload/bootstrap strip vs download stall).
func TestH3FakeIperfParamsReachTarget(t *testing.T) {
	paramsSeen := make(chan []byte, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
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
				buf := make([]byte, 16*1024)
				n, err := conn.Read(buf)
				if n > 0 {
					paramsSeen <- append([]byte(nil), buf[:n]...)
				}
				if err != nil {
					return
				}
				payload := bytes.Repeat([]byte("B"), 64*1024)
				_, _ = conn.Write(payload)
			}(c)
		}
	}()

	proxyPort := startInProcessTCPConnectProxy(t, connectStreamRelayHandler)
	socksPort := startH3ConnectStreamSocksRouter(t, proxyPort)
	conn := socksTCPDial(t, socksPort, port)
	if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	banner := make([]byte, 8)
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("banner: %v", err)
	}
	if _, err := conn.Write([]byte("FAKEIPERF")); err != nil {
		t.Fatalf("write params: %v", err)
	}
	select {
	case got := <-paramsSeen:
		t.Logf("target params: %q (%d bytes)", string(got[:min(len(got), 32)]), len(got))
		if !bytes.Contains(got, []byte("FAKEIPERF")) {
			t.Fatalf("target did not see FAKEIPERF in %q", got[:min(len(got), 64)])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("target never received upload params within 5s (bootstrap/strip/upload stall)")
	}
}

// TestH3RealIperf3CookieReachTarget probes whether 37-byte iperf3 cookie reaches onward TCP.
func TestH3RealIperf3CookieReachTarget(t *testing.T) {
	cookieSeen := make(chan []byte, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
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
				n, err := io.ReadFull(conn, cookie)
				if n > 0 {
					cookieSeen <- append([]byte(nil), cookie[:n]...)
				}
				if err != nil {
					return
				}
				payload := bytes.Repeat([]byte("B"), 64*1024)
				_, _ = conn.Write(payload)
			}(c)
		}
	}()

	proxyPort := startInProcessTCPConnectProxy(t, connectStreamRelayHandler)
	socksPort := startH3ConnectStreamSocksRouter(t, proxyPort)
	conn := socksTCPDial(t, socksPort, port)
	if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	wantCookie := testIperf3ClientCookie()
	if _, err := conn.Write(wantCookie); err != nil {
		t.Fatalf("write cookie: %v", err)
	}
	select {
	case got := <-cookieSeen:
		t.Logf("target cookie: %d bytes", len(got))
		if len(got) != iperf3CookieSize {
			t.Fatalf("cookie len=%d want %d", len(got), iperf3CookieSize)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("target never received iperf3 cookie within 5s (upload stall)")
	}
}

// TestH3ConnectStreamSocksRealIperf3UploadFirst (H3-Docker) — real iperf3 sends 37-byte cookie on
// upload before download; bootstrap zeros after cookie poison docker handshake.
func TestH3ConnectStreamSocksRealIperf3UploadFirst(t *testing.T) {
	targetPort := startRealIperf3UploadFirstTarget(t)
	proxyPort := startInProcessTCPConnectProxy(t, connectStreamRelayHandler)
	n := runH3SocksRealIperf3UploadFirst(t, proxyPort, targetPort, int64(h2ConnectStreamSocksMinRead))
	t.Logf("H3 SOCKS real iperf3 upload-first: %d bytes", n)
}

func TestH3ConnectStreamSocksRealIperf3CookieOnlyDownload(t *testing.T) {
	targetPort := startRealIperf3UploadFirstTarget(t)
	proxyPort := startInProcessTCPConnectProxy(t, connectStreamRelayHandler)
	socksPort := startH3ConnectStreamSocksRouter(t, proxyPort)
	conn := socksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write(testIperf3ClientCookie()); err != nil {
		t.Fatalf("write cookie: %v", err)
	}
	n, err := io.Copy(io.Discard, conn)
	if err != nil && n == 0 {
		t.Fatalf("cookie-only copy: %v", err)
	}
	if n < 32*1024 {
		t.Fatalf("cookie-only download short: %d", n)
	}
	t.Logf("cookie-only download: %d bytes", n)
}

func runH3SocksRealIperf3UploadFirst(t *testing.T, proxyPort int, targetPort uint16, minBytes int64) int64 {
	t.Helper()
	socksPort := startH3ConnectStreamSocksRouter(t, proxyPort)
	conn := socksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	cookie := testIperf3ClientCookie()
	params := testIperf3ClientParamsJSON(cookie)

	if _, err := conn.Write(cookie); err != nil {
		t.Fatalf("write iperf3 cookie: %v", err)
	}
	if _, err := conn.Write(params); err != nil {
		t.Fatalf("write iperf3 params: %v", err)
	}

	var dst bytes.Buffer
	n, err := io.Copy(&dst, conn)
	if err != nil && n == 0 {
		t.Fatalf("real iperf3 download: %v", err)
	}
	if n < minBytes {
		t.Fatalf("real iperf3 download short: %d want >= %d", n, minBytes)
	}
	return n
}

// TestH3ConnectStreamSocksFakeIperfDownloadNoPulse (H3-Docker) — fake iperf -R handshake
// with docker iperf -R handshake (banner read + params write + io.Copy download, no upload pulse).
func TestH3ConnectStreamSocksFakeIperfDownloadNoPulse(t *testing.T) {
	targetPort := startH2FakeIperfDownloadTarget(t)
	proxyPort := startInProcessTCPConnectProxy(t, connectStreamRelayHandler)
	n := runH3SocksFakeIperfNoPulse(t, proxyPort, targetPort, int64(h2ConnectStreamSocksMinRead))
	t.Logf("H3 SOCKS fake iperf no-pulse: %d bytes", n)
}

// TestGATEH3IperfReverseHandshakeRouteMbps — prod iperf -R WriteTo (no RTT harness); AGENTS KPI ≥1000 Mbit/s.
func TestGATEH3IperfReverseHandshakeRouteMbps(t *testing.T) {
	dur := connectStreamSynthProdBenchDuration
	targetPort := startH2FakeIperfStreamingDownloadTarget(t)
	proxyPort := startInProcessTCPConnectProxy(t, connectStreamRelayHandler)
	socksPort := startH3ConnectStreamSocksRouter(t, proxyPort)
	conn := socksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(dur + 8*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	banner := make([]byte, 8)
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("read iperf banner: %v", err)
	}
	if string(banner) != "iperf3\r\n" {
		t.Fatalf("banner: got %q", string(banner))
	}
	if _, err := conn.Write([]byte("FAKEIPERF")); err != nil {
		t.Fatalf("write fake iperf params: %v", err)
	}
	n, mbps, err := measureTCPDownloadWriteToMbps(conn, dur)
	if err != nil && n == 0 {
		t.Fatalf("iperf reverse route WriteTo: %v", err)
	}
	t.Logf("iperf reverse route WriteTo: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < connectStreamSynthProdMinMbps {
		t.Fatalf("%s", synthKPIDiagnostic("[H3 iperf -R route]", "tcp_down WriteTo", mbps,
			connectStreamSynthProdMinMbps, "prod path without L256 harness"))
	}
}

// TestH3ConnectStreamSocksFakeIperfNoPulseBootstrapOff (H3-Docker neg) — without dial bootstrap
// upload the iperf -R handshake must stall (reproduces docker 90s hang shape).
func TestH3ConnectStreamSocksFakeIperfNoPulseBootstrapOff(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_BOOTSTRAP_UPLOAD_BYTES", "0")
	targetPort := startH2FakeIperfDownloadTarget(t)
	proxyPort := startInProcessTCPConnectProxy(t, connectStreamRelayHandler)
	socksPort := startH3ConnectStreamSocksRouter(t, proxyPort)
	conn := socksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		banner := make([]byte, 8)
		if _, err := io.ReadFull(conn, banner); err != nil {
			done <- result{err: err}
			return
		}
		if _, err := conn.Write([]byte("FAKEIPERF")); err != nil {
			done <- result{err: err}
			return
		}
		var dst bytes.Buffer
		n, err := io.Copy(&dst, conn)
		done <- result{n: n, err: err}
	}()

	select {
	case r := <-done:
		if r.err != nil && r.n == 0 {
			t.Fatalf("bootstrap=0 fake iperf: %v", r.err)
		}
		if r.n < int64(h2ConnectStreamSocksMinRead) {
			t.Fatalf("bootstrap=0 must stall or short-read: got %d want >= %d (docker hang repro)", r.n, h2ConnectStreamSocksMinRead)
		}
		t.Logf("bootstrap=0 unexpectedly completed: %d bytes", r.n)
	case <-time.After(9 * time.Second):
		t.Log("bootstrap=0 blocked >9s on iperf handshake (expected docker stall shape)")
	}
}

// TestGATEH3TwinConnectStreamSharedQUICDownloadMbps — twin SOCKS on one QUIC; KPI ≥1000 Mbit/s.
func TestGATEH3TwinConnectStreamSharedQUICDownloadMbps(t *testing.T) {
	dur := connectStreamSynthProdBenchDuration
	targetPort := startH2FakeIperfStreamingDownloadTarget(t)
	proxyPort := startInProcessTCPConnectProxy(t, connectStreamRelayHandler)
	session, _ := newConnectStreamH3ProdSession(t, proxyPort)
	socksPort := startH3ConnectStreamSocksRouterWithSession(t, session)

	dialTwin := func() net.Conn {
		t.Helper()
		conn := socksTCPDial(t, socksPort, targetPort)
		if err := conn.SetDeadline(time.Now().Add(dur + 10*time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		return conn
	}
	connPrimary := dialTwin()
	connTwin := dialTwin()

	handshake := func(conn net.Conn) {
		t.Helper()
		banner := make([]byte, 8)
		if _, err := io.ReadFull(conn, banner); err != nil {
			t.Fatalf("read iperf banner: %v", err)
		}
		if _, err := conn.Write([]byte("FAKEIPERF")); err != nil {
			t.Fatalf("write fake iperf params: %v", err)
		}
	}
	handshake(connPrimary)

	twinDone := make(chan struct{})
	go func() {
		defer close(twinDone)
		handshake(connTwin)
		_, _ = io.Copy(io.Discard, connTwin)
	}()

	n, mbps, err := measureTCPDownloadWriteToMbps(connPrimary, dur)
	<-twinDone
	if err != nil && n == 0 {
		t.Fatalf("twin CONNECT download: %v", err)
	}
	t.Logf("twin CONNECT shared QUIC download: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < connectStreamSynthProdMinMbps {
		t.Fatalf("%s", synthKPIDiagnostic("[H3 twin CONNECT]", "tcp_down WriteTo", mbps,
			connectStreamSynthProdMinMbps, "shared QUIC iperf -R"))
	}
}

// TestLocalizeH3TwinConnectStrictL256Ceiling35ms — wire-FC ceiling repro only (~60 Mbit/s max).
func TestLocalizeH3TwinConnectStrictL256Ceiling35ms(t *testing.T) {
	dur := connectStreamSynthProdBenchDuration
	targetPort := startH2FakeIperfStreamingDownloadTarget(t)
	proxyPort := startInProcessTCPConnectProxy(t, connectStreamRelayHandler)
	session, _ := newConnectStreamH3ProdSession(t, proxyPort)
	socksPort := startH3ConnectStreamSocksRouterWithSession(t, session)

	dialTwin := func() net.Conn {
		t.Helper()
		conn := socksTCPDial(t, socksPort, targetPort)
		if err := conn.SetDeadline(time.Now().Add(dur + 10*time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		return conn
	}
	connPrimary := benchWindowedBidiLinkStrictH3L256().wrap(dialTwin())
	connTwin := dialTwin()

	handshake := func(conn net.Conn) {
		t.Helper()
		banner := make([]byte, 8)
		if _, err := io.ReadFull(conn, banner); err != nil {
			t.Fatalf("read iperf banner: %v", err)
		}
		if _, err := conn.Write([]byte("FAKEIPERF")); err != nil {
			t.Fatalf("write fake iperf params: %v", err)
		}
	}
	handshake(connPrimary)

	twinDone := make(chan struct{})
	go func() {
		defer close(twinDone)
		handshake(connTwin)
		_, _ = io.Copy(io.Discard, connTwin)
	}()

	n, mbps, err := measureTCPDownloadWriteToMbps(connPrimary, dur)
	<-twinDone
	if err != nil && n == 0 {
		t.Fatalf("twin strict windowed download: %v", err)
	}
	t.Logf("twin CONNECT strict L256 windowed 35ms: %.1f Mbit/s (%d bytes)", mbps, n)
	assertLocalizeStrictL256Ceiling35ms(t, "twin strict L256 handshake", mbps)
}

// TestLocalizeH3TwinConnectStrictNoParamsL256Ceiling35ms — real iperf -R bulk leg (no C2S params on download CONNECT).
func TestLocalizeH3TwinConnectStrictNoParamsL256Ceiling35ms(t *testing.T) {
	dur := connectStreamSynthProdBenchDuration
	targetPort := startH2FakeIperfStreamingDownloadTarget(t)
	proxyPort := startInProcessTCPConnectProxy(t, connectStreamRelayHandler)
	session, _ := newConnectStreamH3ProdSession(t, proxyPort)
	socksPort := startH3ConnectStreamSocksRouterWithSession(t, session)

	dialTwin := func() net.Conn {
		t.Helper()
		conn := socksTCPDial(t, socksPort, targetPort)
		if err := conn.SetDeadline(time.Now().Add(dur + 10*time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		return conn
	}
	connPrimary := benchWindowedBidiLinkStrictH3L256().wrap(dialTwin())
	connTwin := dialTwin()

	readBanner := func(conn net.Conn) {
		t.Helper()
		banner := make([]byte, 8)
		if _, err := io.ReadFull(conn, banner); err != nil {
			t.Fatalf("read iperf banner: %v", err)
		}
	}
	readBanner(connPrimary)

	twinDone := make(chan struct{})
	go func() {
		defer close(twinDone)
		readBanner(connTwin)
		if _, err := connTwin.Write([]byte("FAKEIPERF")); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, connTwin)
	}()

	n, mbps, err := measureTCPDownloadWriteToMbps(connPrimary, dur)
	<-twinDone
	if err != nil && n == 0 {
		t.Fatalf("twin no-params primary download: %v", err)
	}
	t.Logf("twin CONNECT no-params primary strict L256 35ms: %.1f Mbit/s (%d bytes)", mbps, n)
	assertLocalizeStrictL256Ceiling35ms(t, "twin no-params primary", mbps)
}

// TestLocalizeH3StrictL256CopyCeiling35ms — iperf Read/io.Copy path under L256/35ms harness.
func TestLocalizeH3StrictL256CopyCeiling35ms(t *testing.T) {
	dur := connectStreamSynthProdBenchDuration
	targetPort := startH2FakeIperfStreamingDownloadTarget(t)
	proxyPort := startInProcessTCPConnectProxy(t, connectStreamRelayHandler)
	session, _ := newConnectStreamH3ProdSession(t, proxyPort)
	socksPort := startH3ConnectStreamSocksRouterWithSession(t, session)

	conn := benchWindowedBidiLinkStrictH3L256().wrap(socksTCPDial(t, socksPort, targetPort))
	if err := conn.SetDeadline(time.Now().Add(dur + 10*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	banner := make([]byte, 8)
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("read iperf banner: %v", err)
	}
	if _, err := conn.Write([]byte("FAKEIPERF")); err != nil {
		t.Fatalf("write fake iperf params: %v", err)
	}
	n, mbps, err := measureTCPDownloadCopyMbps(conn, dur)
	if err != nil && n == 0 {
		t.Fatalf("twin strict copy download: %v", err)
	}
	t.Logf("twin CONNECT strict L256 copy 35ms: %.1f Mbit/s (%d bytes)", mbps, n)
	assertLocalizeStrictL256Ceiling35ms(t, "strict L256 io.Copy", mbps)
}

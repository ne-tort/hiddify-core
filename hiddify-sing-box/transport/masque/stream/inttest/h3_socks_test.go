package inttest_test

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	masque "github.com/sagernet/sing-box/transport/masque"
)

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

	proxyPort := masque.InttestStartInProcessTCPConnectStreamRelayProxy(t)
	socksPort := masque.InttestStartH3ConnectStreamSocksRouter(t, proxyPort)
	conn := masque.InttestSocksTCPDial(t, socksPort, port)
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
				cookie := make([]byte, masque.InttestIperf3CookieSize())
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

	proxyPort := masque.InttestStartInProcessTCPConnectStreamRelayProxy(t)
	socksPort := masque.InttestStartH3ConnectStreamSocksRouter(t, proxyPort)
	conn := masque.InttestSocksTCPDial(t, socksPort, port)
	if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	wantCookie := masque.InttestTestIperf3ClientCookie()
	if _, err := conn.Write(wantCookie); err != nil {
		t.Fatalf("write cookie: %v", err)
	}
	select {
	case got := <-cookieSeen:
		t.Logf("target cookie: %d bytes", len(got))
		if len(got) != masque.InttestIperf3CookieSize() {
			t.Fatalf("cookie len=%d want %d", len(got), masque.InttestIperf3CookieSize())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("target never received iperf3 cookie within 5s (upload stall)")
	}
}

func TestH3ConnectStreamSocksRealIperf3UploadFirst(t *testing.T) {
	targetPort := masque.InttestStartRealIperf3UploadFirstTarget(t)
	proxyPort := masque.InttestStartInProcessTCPConnectStreamRelayProxy(t)
	n := masque.InttestRunH3SocksRealIperf3UploadFirst(t, proxyPort, targetPort, int64(masque.InttestH2ConnectStreamSocksMinRead()))
	t.Logf("H3 SOCKS real iperf3 upload-first: %d bytes", n)
}

func TestH3ConnectStreamSocksRealIperf3CookieOnlyDownload(t *testing.T) {
	targetPort := masque.InttestStartRealIperf3UploadFirstTarget(t)
	proxyPort := masque.InttestStartInProcessTCPConnectStreamRelayProxy(t)
	socksPort := masque.InttestStartH3ConnectStreamSocksRouter(t, proxyPort)
	conn := masque.InttestSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write(masque.InttestTestIperf3ClientCookie()); err != nil {
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

func TestH3ConnectStreamSocksFakeIperfDownloadNoPulse(t *testing.T) {
	targetPort := masque.InttestStartH2FakeIperfDownloadTarget(t)
	proxyPort := masque.InttestStartInProcessTCPConnectStreamRelayProxy(t)
	n := masque.InttestRunH3SocksFakeIperfNoPulse(t, proxyPort, targetPort, int64(masque.InttestH2ConnectStreamSocksMinRead()))
	t.Logf("H3 SOCKS fake iperf no-pulse: %d bytes", n)
}

func TestH3ConnectStreamSocksFakeIperfNoPulseBootstrapOff(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_BOOTSTRAP_UPLOAD_BYTES", "0")
	targetPort := masque.InttestStartH2FakeIperfDownloadTarget(t)
	proxyPort := masque.InttestStartInProcessTCPConnectStreamRelayProxy(t)
	socksPort := masque.InttestStartH3ConnectStreamSocksRouter(t, proxyPort)
	conn := masque.InttestSocksTCPDial(t, socksPort, targetPort)
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
		if r.n < int64(masque.InttestH2ConnectStreamSocksMinRead()) {
			t.Fatalf("bootstrap=0 must stall or short-read: got %d want >= %d (docker hang repro)", r.n, masque.InttestH2ConnectStreamSocksMinRead())
		}
		t.Logf("bootstrap=0 unexpectedly completed: %d bytes", r.n)
	case <-time.After(9 * time.Second):
		t.Log("bootstrap=0 blocked >9s on iperf handshake (expected docker stall shape)")
	}
}

func TestLocalizeH3TwinConnectStrictL256Ceiling35ms(t *testing.T) {
	dur := masque.InttestConnectStreamSynthProdBenchDuration()
	targetPort := masque.InttestStartH2FakeIperfStreamingDownloadTarget(t)
	proxyPort := masque.InttestStartInProcessTCPConnectStreamRelayProxy(t)
	session := masque.InttestNewConnectStreamH3ProdSession(t, proxyPort)
	socksPort := masque.InttestStartH3ConnectStreamSocksRouterWithSession(t, session)

	dialTwin := func() net.Conn {
		t.Helper()
		conn := masque.InttestSocksTCPDial(t, socksPort, targetPort)
		if err := conn.SetDeadline(time.Now().Add(dur + 10*time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		return conn
	}
	connPrimary := masque.InttestWrapBenchWindowedBidiLinkStrictH3L256(dialTwin())
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

	n, mbps, err := masque.InttestMeasureTCPDownloadWriteToMbps(connPrimary, dur)
	<-twinDone
	if err != nil && n == 0 {
		t.Fatalf("twin strict windowed download: %v", err)
	}
	t.Logf("twin CONNECT strict L256 windowed 35ms: %.1f Mbit/s (%d bytes)", mbps, n)
	masque.InttestAssertLocalizeStrictL256Ceiling35ms(t, "twin strict L256 handshake", mbps)
}

func TestLocalizeH3TwinConnectStrictNoParamsL256Ceiling35ms(t *testing.T) {
	dur := masque.InttestConnectStreamSynthProdBenchDuration()
	targetPort := masque.InttestStartH2FakeIperfStreamingDownloadTarget(t)
	proxyPort := masque.InttestStartInProcessTCPConnectStreamRelayProxy(t)
	session := masque.InttestNewConnectStreamH3ProdSession(t, proxyPort)
	socksPort := masque.InttestStartH3ConnectStreamSocksRouterWithSession(t, session)

	dialTwin := func() net.Conn {
		t.Helper()
		conn := masque.InttestSocksTCPDial(t, socksPort, targetPort)
		if err := conn.SetDeadline(time.Now().Add(dur + 10*time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		return conn
	}
	connPrimary := masque.InttestWrapBenchWindowedBidiLinkStrictH3L256(dialTwin())
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

	n, mbps, err := masque.InttestMeasureTCPDownloadWriteToMbps(connPrimary, dur)
	<-twinDone
	if err != nil && n == 0 {
		t.Fatalf("twin no-params primary download: %v", err)
	}
	t.Logf("twin CONNECT no-params primary strict L256 35ms: %.1f Mbit/s (%d bytes)", mbps, n)
	masque.InttestAssertLocalizeStrictL256Ceiling35ms(t, "twin no-params primary", mbps)
}

func TestLocalizeH3StrictL256CopyCeiling35ms(t *testing.T) {
	dur := masque.InttestConnectStreamSynthProdBenchDuration()
	targetPort := masque.InttestStartH2FakeIperfStreamingDownloadTarget(t)
	proxyPort := masque.InttestStartInProcessTCPConnectStreamRelayProxy(t)
	session := masque.InttestNewConnectStreamH3ProdSession(t, proxyPort)
	socksPort := masque.InttestStartH3ConnectStreamSocksRouterWithSession(t, session)

	conn := masque.InttestWrapBenchWindowedBidiLinkStrictH3L256(masque.InttestSocksTCPDial(t, socksPort, targetPort))
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
	n, mbps, err := masque.InttestMeasureTCPDownloadCopyMbps(conn, dur)
	if err != nil && n == 0 {
		t.Fatalf("twin strict copy download: %v", err)
	}
	t.Logf("twin CONNECT strict L256 copy 35ms: %.1f Mbit/s (%d bytes)", mbps, n)
	masque.InttestAssertLocalizeStrictL256Ceiling35ms(t, "strict L256 io.Copy", mbps)
}

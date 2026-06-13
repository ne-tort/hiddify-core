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
	mh2 "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/sagernet/sing-box/transport/masque/session"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	"golang.org/x/net/http2"
)

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
		relayErr := strm.RelayTCPTunnel(r.Context(), target, r.Body, w)
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

// TestH2ConnectStreamTCPUploadWriteBannerNoConcurrentRead verifies bulk upload via Write (not
// ReadFrom/io.Copy) when the onward TCP server sends an iperf banner without a concurrent client Read.
func TestH2ConnectStreamTCPUploadWriteBannerNoConcurrentRead(t *testing.T) {
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
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("iperf3\r\n"))
				_, _ = io.Copy(io.Discard, conn)
			}(c)
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

	uploadDone := make(chan error, 1)
	go func() {
		payload := make([]byte, 256*1024)
		var total int
		for total < 512*1024 {
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
		if err != nil && err != io.EOF {
			t.Fatalf("upload via Write without concurrent read: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("upload Write blocked >8s without concurrent read while server sent banner (H2 drain expected)")
	}
}

// TestH2ConnectStreamTCPUploadServerBannerNoConcurrentRead verifies bulk upload succeeds when
// the onward TCP server sends an iperf-shaped banner on download without a concurrent client Read
// (docker connect-stream-h2 / connect-ip-h2 hang shape; MASQUE_H2_BIDI_DOWNLOAD_DRAIN must run).
func TestH2ConnectStreamTCPUploadServerBannerNoConcurrentRead(t *testing.T) {
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
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("iperf3\r\n"))
				_, _ = io.Copy(io.Discard, conn)
			}(c)
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

	uploadDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, io.LimitReader(&zeroReader{}, 512*1024))
		uploadDone <- err
	}()

	select {
	case err := <-uploadDone:
		if err != nil && err != io.EOF {
			t.Fatalf("upload without concurrent read: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("upload blocked >8s without concurrent read while server sent banner (H2 drain expected)")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func startH2ConnectStreamUploadTarget(t *testing.T) uint16 {
	t.Helper()
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upload target: %v", err)
	}
	t.Cleanup(func() { _ = targetLn.Close() })
	port := uint16(targetLn.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return port
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

func benchConnectStreamH2UploadLayer(t *testing.T, layer string, link bidiLink, duration time.Duration) connectStreamBenchResult {
	t.Helper()
	if layer == "L0" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return connectStreamBenchResult{layer: layer, err: err}
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			_, _ = io.Copy(io.Discard, c)
		}()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return connectStreamBenchResult{layer: layer, err: err}
		}
		defer conn.Close()
		n, mbps, err := measureTCPUploadMbps(conn, duration)
		return connectStreamBenchResult{layer: layer, mbps: mbps, bytes: n, err: err}
	}

	targetPort := startH2ConnectStreamUploadTarget(t)
	conn := dialH2ConnectStreamBench(t, targetPort)
	if link != nil {
		conn = link.wrap(conn)
	}
	n, mbps, err := measureTCPUploadMbps(conn, duration)
	return connectStreamBenchResult{layer: layer, mbps: mbps, bytes: n, err: err}
}

func benchConnectStreamH2DownloadLayerWriteTo(t *testing.T, layer string, link bidiLink, duration time.Duration) connectStreamBenchResult {
	t.Helper()
	if layer == "L0" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return connectStreamBenchResult{layer: layer, err: err}
		}
		defer ln.Close()
		buf := make([]byte, 256*1024)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := c.Write(buf); err != nil {
					return
				}
			}
		}()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return connectStreamBenchResult{layer: layer, err: err}
		}
		defer conn.Close()
		n, mbps, err := measureTCPDownloadWriteToMbps(readAsWriterTo{conn}, duration)
		return connectStreamBenchResult{layer: layer, mbps: mbps, bytes: n, err: err}
	}

	targetPort := startH2ConnectStreamDownloadTarget(t)
	conn := dialH2ConnectStreamBench(t, targetPort)
	if link != nil {
		conn = link.wrap(conn)
	}
	n, mbps, err := measureTCPDownloadWriteToMbps(conn, duration)
	return connectStreamBenchResult{layer: layer, mbps: mbps, bytes: n, err: err}
}

func runConnectStreamH2DuplexWriteToBench(t *testing.T, link bidiLink, minMbps float64) {
	t.Helper()
	const duration = localizeBenchDuration
	const pulseBytes = 32 * 1024

	targetPort := startH2ConnectStreamDownloadTarget(t)
	conn := dialH2ConnectStreamBench(t, targetPort)
	if link != nil {
		conn = link.wrap(conn)
	}

	downloadDone := make(chan connectStreamBenchResult, 1)
	go func() {
		n, mbps, err := measureTCPDownloadWriteToMbps(conn, duration)
		downloadDone <- connectStreamBenchResult{layer: "download", mbps: mbps, bytes: n, err: err}
	}()

	pulse := make([]byte, pulseBytes)
	pulseDeadline := time.Now().Add(duration)
	for time.Now().Before(pulseDeadline) {
		if _, err := conn.Write(pulse); err != nil {
			t.Fatalf("upload pulse: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	dl := <-downloadDone
	if dl.err != nil {
		t.Fatalf("duplex WriteTo download: %v", dl.err)
	}
	t.Logf("h2 connect-stream duplex WriteTo download: %.1f Mbit/s (%d bytes)", dl.mbps, dl.bytes)
	if dl.mbps < minMbps {
		t.Fatalf("h2 duplex WriteTo download stalled: %.1f Mbit/s (want >= %.0f)", dl.mbps, minMbps)
	}
}

func dialH2ConnectStreamBench(tb testing.TB, targetPort uint16) net.Conn {
	tb.Helper()
	proxyPort := startInProcessH2TCPConnectStreamProxy(tb)
	rawURL := "https://127.0.0.1:" + strconv.Itoa(proxyPort) + "/masque/tcp/127.0.0.1/" + strconv.Itoa(int(targetPort))
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
	s.Options.TCPDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	s.UDPHTTPLayer.Store(option.MasqueHTTPLayerH2)

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	tb.Cleanup(cancel)

	conn, err := s.dialTCPStreamH2(ctx, tcpURL, s.Options, "127.0.0.1", M.ParseSocksaddrHostPort("127.0.0.1", targetPort))
	if err != nil {
		tb.Fatalf("dial: %v", err)
	}
	tb.Cleanup(func() { _ = conn.Close() })
	return conn
}

const connectStreamH2E2EBenchBytes = 2 * 1024 * 1024

type connectStreamH2E2EBenchSpec struct {
	name string
	link bidiLink
}

func connectStreamH2E2EBenchSpecs() []connectStreamH2E2EBenchSpec {
	return []connectStreamH2E2EBenchSpec{
		{"L1", instantBidiLink{}},
		{"L3", benchWindowedBidiLink()},
	}
}

func runConnectStreamH2E2EDownloadOnce(tb testing.TB, link bidiLink, nbytes int64) (int64, error) {
	tb.Helper()
	targetPort := startH2ConnectStreamDownloadTarget(tb)
	conn := dialH2ConnectStreamBench(tb, targetPort)
	if link != nil {
		conn = link.wrap(conn)
	}
	return drainWriteToFixedBytes(conn, nbytes)
}

// BenchmarkConnectStreamH2EndToEndDownload (S86): H2 CONNECT-stream WriteTo download CPU anchors L1+L3.
func BenchmarkConnectStreamH2EndToEndDownload(b *testing.B) {
	for _, spec := range connectStreamH2E2EBenchSpecs() {
		b.Run(spec.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(connectStreamH2E2EBenchBytes)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				n, err := runConnectStreamH2E2EDownloadOnce(b, spec.link, connectStreamH2E2EBenchBytes)
				if err != nil {
					b.Fatal(err)
				}
				if n < connectStreamH2E2EBenchBytes {
					b.Fatalf("short h2 e2e drain: %d want %d", n, connectStreamH2E2EBenchBytes)
				}
			}
		})
	}
}

// TestMasqueConnectStreamH2LocalizeUpload (S67) localizes H2 CONNECT-stream upload on instant + windowed bidi.
func TestMasqueConnectStreamH2LocalizeUpload(t *testing.T) {
	const duration = localizeBenchDuration

	instant := benchConnectStreamH2UploadLayer(t, "L1", instantBidiLink{}, duration)
	windowed := benchConnectStreamH2UploadLayer(t, "L3", benchWindowedBidiLink(), duration)

	for _, r := range []connectStreamBenchResult{instant, windowed} {
		if r.err != nil {
			t.Fatalf("%s upload: %v", r.layer, r.err)
		}
		t.Logf("h2 connect-stream upload %s: %.1f Mbit/s (%d bytes)", r.layer, r.mbps, r.bytes)
	}

	if instant.mbps < connectStreamLocalizeFastMbps {
		t.Fatalf("h2 upload instant slow: %.1f Mbit/s (want >= %.0f)", instant.mbps, connectStreamLocalizeFastMbps)
	}
	if windowed.mbps < connectStreamLocalizeCeilingMin || windowed.mbps > connectStreamLocalizeCeilingMax {
		t.Fatalf("h2 upload windowed: %.1f Mbit/s (want %.0f–%.0f)", windowed.mbps, connectStreamLocalizeCeilingMin, connectStreamLocalizeCeilingMax)
	}
}

// TestMasqueConnectStreamH2InstantDownloadExceedsVPSKPI (S68) verifies H2 WriteTo download exceeds field KPI (21 Mbit/s).
func TestMasqueConnectStreamH2InstantDownloadExceedsVPSKPI(t *testing.T) {
	const duration = localizeBenchDuration
	r := benchConnectStreamH2DownloadLayerWriteTo(t, "L1", instantBidiLink{}, duration)
	if r.err != nil {
		t.Fatalf("h2 instant WriteTo download: %v", r.err)
	}
	t.Logf("h2 connect-stream instant WriteTo download: %.1f Mbit/s", r.mbps)
	if r.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("h2 instant WriteTo download %.1f Mbit/s (want > %.0f VPS KPI)", r.mbps, connectStreamVPSKPITargetDownMbps)
	}
}

// TestMasqueConnectStreamH2LocalizeBottleneck (S69) localizes H2 CONNECT-stream upload across L0–L3 window model.
func TestMasqueConnectStreamH2LocalizeBottleneck(t *testing.T) {
	const duration = localizeBenchDuration

	l0 := benchConnectStreamH2UploadLayer(t, "L0", nil, duration)
	l1 := benchConnectStreamH2UploadLayer(t, "L1", instantBidiLink{}, duration)
	l2 := benchConnectStreamH2UploadLayer(t, "L2", benchWindowedWideBidiLink(), duration)
	l3 := benchConnectStreamH2UploadLayer(t, "L3", benchWindowedBidiLink(), duration)

	for _, r := range []connectStreamBenchResult{l0, l1, l2, l3} {
		if r.err != nil {
			t.Fatalf("%s: %v", r.layer, r.err)
		}
		t.Logf("h2 connect-stream localize %s upload: %.1f Mbit/s (%d bytes)", r.layer, r.mbps, r.bytes)
	}

	if l1.mbps < connectStreamLocalizeFastMbps {
		t.Fatalf("h2 L1 upload slow: %.1f Mbit/s (want >= %.0f)", l1.mbps, connectStreamLocalizeFastMbps)
	}
	if l3.mbps < connectStreamLocalizeCeilingMin || l3.mbps > connectStreamLocalizeCeilingMax {
		t.Fatalf("h2 L3 upload windowed: %.1f Mbit/s (want %.0f–%.0f)", l3.mbps, connectStreamLocalizeCeilingMin, connectStreamLocalizeCeilingMax)
	}

	v := verdictConnectStreamBottleneck(l0, l1, l2, l3)
	t.Logf("h2 connect-stream localize verdict: %s", v)

	dl := benchConnectStreamH2DownloadLayerWriteTo(t, "L1", instantBidiLink{}, duration)
	if dl.err != nil {
		t.Fatalf("h2 L1 WriteTo download: %v", dl.err)
	}
	t.Logf("h2 connect-stream localize L1 WriteTo download: %.1f Mbit/s (%d bytes)", dl.mbps, dl.bytes)
	if dl.mbps < connectStreamLocalizeFastMbps {
		t.Fatalf("h2 L1 WriteTo download slow: %.1f Mbit/s (want >= %.0f)", dl.mbps, connectStreamLocalizeFastMbps)
	}
}

// TestMasqueConnectStreamH2LocalizeDuplexInstant (S70) checks H2 WriteTo download under upload pulses on instant bidi.
func TestMasqueConnectStreamH2LocalizeDuplexInstant(t *testing.T) {
	runConnectStreamH2DuplexWriteToBench(t, instantBidiLink{}, connectStreamLocalizeFastMbps/4)
}

// TestMasqueConnectStreamH2LocalizeDownloadWriteTo (S98) localizes H2 CONNECT-stream download via
// WriteTo on instant + windowed bidi (prod route writer_to path; replaces legacy Read-path localize).
func TestMasqueConnectStreamH2LocalizeDownloadWriteTo(t *testing.T) {
	const duration = localizeBenchDuration

	instant := benchConnectStreamH2DownloadLayerWriteTo(t, "L1", instantBidiLink{}, duration)
	windowed := benchConnectStreamH2DownloadLayerWriteTo(t, "L3", benchWindowedBidiLink(), duration)

	for _, r := range []connectStreamBenchResult{instant, windowed} {
		if r.err != nil {
			t.Fatalf("%s WriteTo download: %v", r.layer, r.err)
		}
		t.Logf("h2 connect-stream download %s WriteTo: %.1f Mbit/s (%d bytes)", r.layer, r.mbps, r.bytes)
	}

	if instant.mbps < connectStreamLocalizeFastMbps {
		t.Fatalf("h2 download instant WriteTo slow: %.1f Mbit/s (want >= %.0f)", instant.mbps, connectStreamLocalizeFastMbps)
	}
	if windowed.mbps < connectStreamLocalizeCeilingMin || windowed.mbps > connectStreamLocalizeCeilingMax {
		t.Fatalf("h2 download windowed WriteTo: %.1f Mbit/s (want %.0f–%.0f)", windowed.mbps, connectStreamLocalizeCeilingMin, connectStreamLocalizeCeilingMax)
	}
}

// TestMasqueConnectStreamH2LocalizeDuplexWriteTo (S98) checks H2 WriteTo download under upload pulses
// on windowed bidi (complements S70 instant duplex WriteTo).
func TestMasqueConnectStreamH2LocalizeDuplexWriteTo(t *testing.T) {
	runConnectStreamH2DuplexWriteToBench(t, benchWindowedBidiLink(), connectStreamLocalizeCeilingMin/2)
}

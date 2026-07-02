package masque

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/url"
	"strconv"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/session"
)
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
func runConnectStreamH2DuplexWriteToNoPulseBenchMbps(t *testing.T, link bidiLink, minMbps, maxMbps float64) {
	t.Helper()
	const duration = localizeBenchDuration

	targetPort := startH2ConnectStreamDownloadTarget(t)
	conn := dialH2ConnectStreamBench(t, targetPort)
	if link != nil {
		conn = link.wrap(conn)
	}

	n, mbps, err := measureTCPDownloadWriteToMbps(conn, duration)
	if err != nil && n == 0 {
		t.Fatalf("duplex WriteTo download without upload pulse: %v", err)
	}
	t.Logf("h2 connect-stream duplex WriteTo no-pulse: %.1f Mbit/s (%d bytes)", mbps, n)
	if n < localizeBenchMinBytes {
		t.Fatalf("h2 duplex WriteTo no-pulse stalled: %d bytes (want >= %d); mbps=%.1f",
			n, localizeBenchMinBytes, mbps)
	}
	if maxMbps > 0 && mbps > maxMbps {
		t.Fatalf("h2 duplex WriteTo no-pulse: %.1f Mbit/s (want <= %.1f)", mbps, maxMbps)
	}
	if mbps <= minMbps {
		t.Fatalf("h2 duplex WriteTo no-pulse: %.1f Mbit/s (want > %.0f KPI)", mbps, minMbps)
	}
}

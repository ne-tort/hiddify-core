package masque

import (
	"context"
	"crypto/tls"
	"fmt"
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
		rf, ok := conn.(io.ReaderFrom)
		if !ok {
			uploadDone <- fmt.Errorf("conn lacks io.ReaderFrom")
			return
		}
		_, err := rf.ReadFrom(io.LimitReader(&zeroReader{}, 512*1024))
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

// TestH2ConnectStreamTCPUploadWriteBannerNoConcurrentRead verifies bulk upload via ReadFrom
// (prod route reader_from path) when the onward server sends an iperf banner without client Read.
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
		rf, ok := conn.(io.ReaderFrom)
		if !ok {
			uploadDone <- fmt.Errorf("conn lacks io.ReaderFrom")
			return
		}
		_, err := rf.ReadFrom(io.LimitReader(&zeroReader{}, 512*1024))
		uploadDone <- err
	}()

	select {
	case err := <-uploadDone:
		if err != nil && err != io.EOF {
			t.Fatalf("upload via ReadFrom without concurrent read: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("upload ReadFrom blocked >8s without concurrent read while server sent banner (H2 drain expected)")
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
		rf, ok := conn.(io.ReaderFrom)
		if !ok {
			uploadDone <- fmt.Errorf("conn lacks io.ReaderFrom")
			return
		}
		_, err := rf.ReadFrom(io.LimitReader(&zeroReader{}, 512*1024))
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

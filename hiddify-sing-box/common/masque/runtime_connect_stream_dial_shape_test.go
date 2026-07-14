package masque

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	T "github.com/sagernet/sing-box/transport/masque"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
)

var runtimeConnectStreamTestTLS *tls.Config

func init() {
	caTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(2026),
		Subject:               pkix.Name{},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("runtime_connect_stream_dial_shape_test: generate CA key: " + err.Error())
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTempl, caTempl, &caKey.PublicKey, caKey)
	if err != nil {
		panic("runtime_connect_stream_dial_shape_test: create CA cert: " + err.Error())
	}
	ca, err := x509.ParseCertificate(caBytes)
	if err != nil {
		panic("runtime_connect_stream_dial_shape_test: parse CA: " + err.Error())
	}
	leafTempl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost", "127.0.0.1"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("runtime_connect_stream_dial_shape_test: generate leaf key: " + err.Error())
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTempl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		panic("runtime_connect_stream_dial_shape_test: create leaf: " + err.Error())
	}
	runtimeConnectStreamTestTLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafBytes},
			PrivateKey:  leafKey,
		}},
		NextProtos: []string{http3.NextProtoH3},
	}
}

func assertRuntimeConnectStreamProdDialShape(t *testing.T, conn net.Conn) {
	t.Helper()
	shape := strm.ProdDialShapeOf(conn)
	if !shape.OK() {
		t.Fatalf("runtime dial conn lacks prod shape: %+v", shape)
	}
}

func startRuntimeConnectStreamH3Stack(t *testing.T) (Runtime, uint16) {
	t.Helper()

	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	go func() {
		for {
			c, acceptErr := targetLn.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 32*1024)
				for i := range buf {
					buf[i] = 'z'
				}
				for {
					if _, writeErr := c.Write(buf); writeErr != nil {
						return
					}
				}
			}(c)
		}
	}()
	t.Cleanup(func() { _ = targetLn.Close() })
	targetPort := uint16(targetLn.Addr().(*net.TCPAddr).Port)

	proxyPort := startRuntimeInProcessTCPConnectProxy(t)
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)

	rt := NewRuntime(T.CoreClientFactory{}, RuntimeOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err := rt.Start(waitCtx); err != nil {
		t.Fatalf("runtime start: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	return rt, targetPort
}

func startRuntimeInProcessTCPConnectProxy(tb testing.TB) int {
	tb.Helper()
	quicConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		tb.Fatalf("listen quic udp: %v", err)
	}
	proxyPort := quicConn.LocalAddr().(*net.UDPAddr).Port
	serverTLS := runtimeConnectStreamTestTLS

	mux := http.NewServeMux()
	mux.HandleFunc("/masque/tcp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		targetHost := r.PathValue("target_host")
		targetPort := r.PathValue("target_port")
		upstream, dialErr := net.DialTimeout("tcp", net.JoinHostPort(targetHost, targetPort), 2*time.Second)
		if dialErr != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		_ = upstream.SetDeadline(time.Now().Add(30 * time.Second))
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		_ = strm.RelayTCPTunnel(r.Context(), upstream, r.Body, w)
	})
	server := http3.Server{
		TLSConfig:       serverTLS,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: true,
		Handler:         mux,
	}
	var serveWG sync.WaitGroup
	serveWG.Add(1)
	go func() {
		defer serveWG.Done()
		_ = server.Serve(quicConn)
	}()
	tb.Cleanup(func() {
		_ = server.Close()
		serveWG.Wait()
		_ = quicConn.Close()
	})
	time.Sleep(20 * time.Millisecond)
	return proxyPort
}

// TestRuntimeConnectStreamDialShape (S51): CoreClientFactory → Runtime.Start → DialContext
// must return stream.TunnelConn wired for route writer_to bulk download.
func TestRuntimeConnectStreamDialShape(t *testing.T) {
	rt, targetPort := startRuntimeConnectStreamH3Stack(t)
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	conn, err := rt.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", targetPort))
	if err != nil {
		t.Fatalf("runtime dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	assertRuntimeConnectStreamProdDialShape(t, conn)
}

var errRuntimeBenchDuration = errors.New("masque: runtime bench duration elapsed")

type runtimeBenchWriteToSink struct {
	deadline time.Time
	total    int64
}

func (s *runtimeBenchWriteToSink) Write(p []byte) (int, error) {
	if time.Now().After(s.deadline) {
		return 0, errRuntimeBenchDuration
	}
	s.total += int64(len(p))
	return len(p), nil
}

// TestEndpointRuntimeSessionDownloadWriteToChain (S78): Runtime → session → TunnelConn.WriteTo
// must drain download bytes (prod route writer_to chain, not Read-only stub).
func TestEndpointRuntimeSessionDownloadWriteToChain(t *testing.T) {
	rt, targetPort := startRuntimeConnectStreamH3Stack(t)
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	conn, err := rt.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", targetPort))
	if err != nil {
		t.Fatalf("runtime dial: %v", err)
	}
	defer conn.Close()
	assertRuntimeConnectStreamProdDialShape(t, conn)

	wt, ok := conn.(io.WriterTo)
	if !ok {
		t.Fatal("conn must implement io.WriterTo after runtime dial")
	}
	duration := 120 * time.Millisecond
	deadline := time.Now().Add(duration)
	_ = conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})
	sink := &runtimeBenchWriteToSink{deadline: deadline}
	_, err = wt.WriteTo(sink)
	if err != nil && err != errRuntimeBenchDuration && err != io.EOF && sink.total == 0 {
		t.Fatalf("WriteTo drain: %v", err)
	}
	if sink.total < 32*1024 {
		t.Fatalf("WriteTo drained %d bytes, want >= 32 KiB", sink.total)
	}
}

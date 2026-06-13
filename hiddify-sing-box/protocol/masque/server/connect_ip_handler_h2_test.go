package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	mh2 "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"

	_ "github.com/sagernet/sing-box/internal/http2xconnect"
)

var connectIPHandlerH2TestTLS *tls.Config

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
		panic("connect_ip_handler_h2_test: ca key: " + err.Error())
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
		panic("connect_ip_handler_h2_test: leaf key: " + err.Error())
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTempl, caTempl, &leafKey.PublicKey, caKey)
	if err != nil {
		panic("connect_ip_handler_h2_test: leaf cert: " + err.Error())
	}
	connectIPHandlerH2TestTLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafBytes},
			PrivateKey:  leafKey,
		}},
		NextProtos: []string{http2.NextProtoTLS, "http/1.1"},
	}
}

func startConnectIPHandlerH2Server(t *testing.T) (port int, ipTemplate *uritemplate.Template) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port = ln.Addr().(*net.TCPAddr).Port
	rawTpl := fmt.Sprintf("https://127.0.0.1:%d/masque/ip", port)
	ipTemplate, err = uritemplate.New(rawTpl)
	if err != nil {
		t.Fatalf("template: %v", err)
	}

	host := ConnectIPHandlerHost{
		Tag:     "h2-test",
		Type:    "masque",
		Options: option.MasqueEndpointOptions{AllowPrivateTargets: true},
		RequestForParse: func(r *http.Request, _ *uritemplate.Template, _ bool) *http.Request {
			return r
		},
		RelaxAuthority: func(option.MasqueEndpointOptions, string) bool { return true },
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/masque/ip", func(w http.ResponseWriter, r *http.Request) {
		_ = http.NewResponseController(w).EnableFullDuplex()
		HandleConnectIPRequest(host, w, r, ipTemplate)
	})

	serverTLS := connectIPHandlerH2TestTLS.Clone()
	tlsLn := tls.NewListener(ln, serverTLS)
	srv := &http.Server{Handler: mux}
	if err := http2.ConfigureServer(srv, mh2.BulkHTTP2ServerConfig()); err != nil {
		t.Fatalf("configure http2: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = srv.Serve(tlsLn)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		wg.Wait()
	})
	time.Sleep(20 * time.Millisecond)
	return port, ipTemplate
}

func dialConnectIPHandlerH2Client(t *testing.T, template *uritemplate.Template, port int) *connectip.Conn {
	t.Helper()
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "127.0.0.1",
		NextProtos:         []string{http2.NextProtoTLS},
	}
	tr := &http2.Transport{
		TLSClientConfig: tlsCfg,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			if cfg == nil {
				cfg = tlsCfg
			}
			var d net.Dialer
			conn, err := d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(conn, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, resp, err := connectip.DialHTTP2(ctx, tr, template, connectip.DialOptions{})
	if err != nil {
		t.Fatalf("DialHTTP2: %v", err)
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		code := 0
		if resp != nil {
			code = resp.StatusCode
		}
		t.Fatalf("status=%d want 200", code)
	}
	if got := resp.Header.Get(http3.CapsuleProtocolHeader); got == "" {
		t.Fatal("missing Capsule-Protocol on CONNECT-IP H2 response")
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func waitConnectIPAssignedPrefixes(t *testing.T, conn *connectip.Conn) []netip.Prefix {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	prefixes, err := conn.LocalPrefixes(ctx)
	if err != nil {
		t.Fatalf("LocalPrefixes: %v", err)
	}
	if len(prefixes) == 0 {
		t.Fatal("expected non-empty ADDRESS_ASSIGN prefixes from HandleConnectIPRequest bootstrap")
	}
	return prefixes
}

// TestHandleConnectIPRequestH2PacketPlaneReadWrite exercises HandleConnectIPRequest over HTTP/2
// Extended CONNECT (EnableFullDuplex + capsule body) through client WritePacket/ReadPacket.
func TestHandleConnectIPRequestH2PacketPlaneReadWrite(t *testing.T) {
	_, template := startConnectIPHandlerH2Server(t)
	port := templatePort(template)
	clientConn := dialConnectIPHandlerH2Client(t, template, port)
	prefixes := waitConnectIPAssignedPrefixes(t, clientConn)

	local4 := prefixes[0].Addr()
	pktSess := cip.NewClientPacketSession(cip.ClientPacketSessionConfig{
		Conn:      clientConn,
		OverlayH2: true,
	})
	waitIngress := startH2ConnectIPIngressRelay(pktSess)
	t.Cleanup(func() {
		_ = clientConn.Close()
		waitIngress()
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ConnectIPRouteActiveCount() > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if ConnectIPRouteActiveCount() == 0 {
		t.Fatal("expected active RouteConnectIPBlocked while H2 handler is serving")
	}

	probe := makeIPv4UDPPacket(
		local4,
		netip.MustParseAddr("10.0.0.1"),
		40000,
		53,
		[]byte("probe"),
	)
	if _, err := clientConn.WritePacket(probe); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	readCtx, readCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer readCancel()
	readBuf := make([]byte, 2048)
	_, readErr := pktSess.ReadPacketWithContext(readCtx, readBuf)
	if readErr != nil && !errors.Is(readErr, context.DeadlineExceeded) && !errors.Is(readErr, context.Canceled) {
		var netErr net.Error
		if !(errors.As(readErr, &netErr) && netErr.Timeout()) {
			t.Fatalf("ReadPacket after WritePacket: %v", readErr)
		}
	}
}

// TestHandleConnectIPRequestH2RecycleUploadDownload verifies burst upload WritePacket traffic
// does not poison the H2 overlay before a fresh download ReadPacket/WritePacket on the same session.
func TestHandleConnectIPRequestH2RecycleUploadDownload(t *testing.T) {
	_, template := startConnectIPHandlerH2Server(t)
	port := templatePort(template)
	clientConn := dialConnectIPHandlerH2Client(t, template, port)
	prefixes := waitConnectIPAssignedPrefixes(t, clientConn)

	local4 := prefixes[0].Addr()
	pktSess := cip.NewClientPacketSession(cip.ClientPacketSessionConfig{
		Conn:      clientConn,
		OverlayH2: true,
	})
	waitIngress := startH2ConnectIPIngressRelay(pktSess)
	t.Cleanup(func() {
		_ = clientConn.Close()
		waitIngress()
	})

	uploadPkt := makeIPv4UDPPacket(
		local4,
		netip.MustParseAddr("10.0.0.2"),
		41000,
		53,
		bytes.Repeat([]byte{'u'}, 512),
	)
	var uploadBytes int
	for i := 0; i < 64; i++ {
		if _, err := clientConn.WritePacket(uploadPkt); err != nil {
			t.Fatalf("upload WritePacket[%d]: %v", i, err)
		}
		uploadBytes += len(uploadPkt)
	}

	readCtx, readCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer readCancel()
	readBuf := make([]byte, 2048)
	_, _ = pktSess.ReadPacketWithContext(readCtx, readBuf)

	downloadPkt := makeIPv4UDPPacket(
		local4,
		netip.MustParseAddr("10.0.0.3"),
		42000,
		53,
		bytes.Repeat([]byte{'d'}, 512),
	)
	if _, err := clientConn.WritePacket(downloadPkt); err != nil {
		t.Fatalf("download WritePacket after upload recycle: %v", err)
	}

	readCtx2, readCancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer readCancel2()
	_, readErr := pktSess.ReadPacketWithContext(readCtx2, readBuf)
	if readErr != nil && !errors.Is(readErr, context.DeadlineExceeded) && !errors.Is(readErr, context.Canceled) {
		var netErr net.Error
		if !(errors.As(readErr, &netErr) && netErr.Timeout()) {
			t.Fatalf("ReadPacket after recycle: %v", readErr)
		}
	}
	t.Logf("H2 overlay recycle: upload_bytes=%d download_write_ok=1", uploadBytes)
}

func startH2ConnectIPIngressRelay(sess *cip.ClientPacketSession) func() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		readBuffer := make([]byte, 64*1024)
		for {
			n, err := sess.ReadPacket(readBuffer)
			if err != nil {
				return
			}
			if n > 0 {
				_ = n
			}
		}
	}()
	return wg.Wait
}

func templatePort(template *uritemplate.Template) int {
	raw := template.Raw()
	hostPort := strings.TrimPrefix(raw, "https://")
	if i := strings.Index(hostPort, "/"); i >= 0 {
		hostPort = hostPort[:i]
	}
	_, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		panic("connect_ip_handler_h2_test: bad template host: " + raw)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		panic("connect_ip_handler_h2_test: bad template port: " + raw)
	}
	return port
}

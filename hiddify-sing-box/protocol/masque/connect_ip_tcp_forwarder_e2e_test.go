package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	TM "github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

// TestMasqueConnectIPTCP_E2E_Local verifies generic MASQUE server CONNECT-IP + tcp_transport=connect_ip
// by dialing a local TCP echo through the in-process server (HTTP/2 MASQUE overlay).
func TestMasqueConnectIPTCP_E2E_Local(t *testing.T) {
	certPath, keyPath := writeMasqueTestServerCertPair(t)

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = echoLn.Close() })
	echoPort := echoLn.Addr().(*net.TCPAddr).Port

	go func() {
		c, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(8 * time.Second))
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err != nil || n == 0 {
			return
		}
		if string(buf[:n]) == "ping" {
			_, _ = c.Write([]byte("pong"))
		}
	}()

	srvPort := pickMasqueE2EFreePort(t)

	logger := log.NewNOPFactory().NewLogger("masque-e2e")

	epRaw, err := NewServerEndpoint(context.Background(), nil, logger, "masque-e2e-srv", option.MasqueEndpointOptions{
		Mode:                option.MasqueModeServer,
		Listen:              "127.0.0.1",
		ListenPort:          uint16(srvPort),
		Certificate:         certPath,
		Key:                 keyPath,
		AllowPrivateTargets: true,
		AllowedTargetPorts:  nil,
		BlockedTargetPorts:  nil,
	})
	if err != nil {
		t.Fatalf("new server endpoint: %v", err)
	}
	srv := epRaw.(*ServerEndpoint)
	if err := srv.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("server start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	deadline := time.Now().Add(5 * time.Second)
	for !srv.IsReady() && time.Now().Before(deadline) {
		time.Sleep(15 * time.Millisecond)
	}
	if !srv.IsReady() {
		t.Fatal("server not ready")
	}
	if srv.tcpTLSListener == nil {
		t.Fatal("server tcp listener nil")
	}
	if got := srv.tcpTLSListener.Addr().(*net.TCPAddr).Port; got != srvPort {
		t.Fatalf("server bound port: got %d want %d", got, srvPort)
	}

	host := fmt.Sprintf("127.0.0.1:%d", srvPort)
	base := "https://" + host

	waitCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	session, err := (TM.CoreClientFactory{}).NewSession(waitCtx, TM.ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(srvPort),
		TransportMode:            option.MasqueTransportModeConnectIP,
		TCPTransport:             option.MasqueTCPTransportConnectIP,
		TemplateIP:               base + "/masque/ip",
		TemplateUDP:              base + "/masque/udp/{target_host}/{target_port}",
		TemplateTCP:              base + "/masque/tcp/{target_host}/{target_port}",
		Insecure:                 true,
		MasqueEffectiveHTTPLayer: "h3",
		TCPDial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, address)
		},
	})
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	dialAddr := M.ParseSocksaddrHostPort("127.0.0.1", uint16(echoPort))
	conn, err := session.DialContext(waitCtx, "tcp", dialAddr)
	if err != nil {
		t.Fatalf("dial tcp over connect_ip: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, 16)
	n, err := conn.Read(reply)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(reply[:n]) != "pong" {
		t.Fatalf("unexpected reply %q", string(reply[:n]))
	}
}

func writeMasqueTestServerCertPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "masque-e2e"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		_ = cf.Close()
		t.Fatal(err)
	}
	_ = cf.Close()

	kf, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		_ = kf.Close()
		t.Fatal(err)
	}
	if err := pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		_ = kf.Close()
		t.Fatal(err)
	}
	_ = kf.Close()
	return certPath, keyPath
}

func pickMasqueE2EFreePort(t *testing.T) int {
	t.Helper()
	for range 128 {
		u, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		port := u.LocalAddr().(*net.UDPAddr).Port
		_ = u.Close()
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		tr, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		_ = tr.Close()
		return port
	}
	t.Fatal("no ephemeral UDP/TCP pair available on 127.0.0.1")
	return 0
}

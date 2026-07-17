package masque

import (
	"github.com/sagernet/sing-box/transport/masque/session"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

func TestMasqueConnectIPRequestParseUsesPathOnly(t *testing.T) {
	t.Parallel()
	template := uritemplate.MustNew("https://127.0.0.1:4438/.well-known/masque/ip")
	req := makeConnectIPTestRequest(t, "https://127.0.0.1:4438/.well-known/masque/ip")
	req.Host = "193.233.216.26:4438"
	// Path-only templates still require matching authority for connect-ip-go ParseRequest;
	// server RequestForParse is now identity — clients must use a matching path prefix.
	if _, err := connectip.ParseRequest(req, template); err == nil {
		t.Fatal("expected connect-ip-go ParseRequest to reject authority mismatch")
	}
	req.Host = "127.0.0.1:4438"
	if _, err := connectip.ParseRequest(req, template); err != nil {
		t.Fatalf("path match with template authority: %v", err)
	}
}

func TestServerEndpointDialContextRejectsInvalidDestinationAsCapability(t *testing.T) {
	endpoint := &ServerEndpoint{}
	_, err := endpoint.DialContext(context.Background(), "tcp", M.Socksaddr{})
	if err == nil {
		t.Fatal("expected invalid destination to be rejected")
	}
	if !errors.Is(err, session.ErrCapability) {
		t.Fatalf("expected ErrCapability for invalid destination, got: %v", err)
	}
	if got := session.ClassifyError(err); got != session.ErrorClassCapability {
		t.Fatalf("expected capability class for invalid destination, got: %s", got)
	}
}

func TestServerEndpointLifecycleStartIsReadyCloseTwice(t *testing.T) {
	certPath, keyPath := writeServerTestCertificate(t)
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			Listen:      "127.0.0.1",
			ListenPort:  0,
			InboundTLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
	}
	if ep.IsReady() {
		t.Fatal("server endpoint must not be ready before Start")
	}
	if err := ep.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("server start failed: %v", err)
	}
	if !ep.IsReady() {
		t.Fatal("server endpoint must be ready immediately after successful Start")
	}
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- ep.Close()
	}()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("first close failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first close timed out (potential lifecycle hang)")
	}
	if ep.IsReady() {
		t.Fatal("server endpoint must not be ready after Close")
	}
	closeDone = make(chan error, 1)
	go func() {
		closeDone <- ep.Close()
	}()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("second close failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second close timed out (close must stay idempotent)")
	}
}

func TestServerEndpointStartInvalidCertificateFailsFast(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "invalid.crt")
	keyPath := filepath.Join(tmpDir, "invalid.key")
	if err := os.WriteFile(certPath, []byte("not-a-certificate"), 0o600); err != nil {
		t.Fatalf("write invalid cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not-a-private-key"), 0o600); err != nil {
		t.Fatalf("write invalid key: %v", err)
	}
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			Listen:      "127.0.0.1",
			ListenPort:  0,
			InboundTLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
	}
	err := ep.Start(adapter.StartStateStart)
	if err == nil {
		t.Fatal("expected Start to fail fast with invalid certificate/key")
	}
	if ep.IsReady() {
		t.Fatal("server endpoint must remain not ready after failed Start")
	}
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- ep.Close()
	}()
	select {
	case closeErr := <-closeDone:
		if closeErr != nil {
			t.Fatalf("close after failed start should stay safe, got: %v", closeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("close after failed start timed out (unexpected lifecycle hang)")
	}
}

func TestServerEndpointStartListenConflictFailsFast(t *testing.T) {
	certPath, keyPath := writeServerTestCertificate(t)
	conflictConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve udp port for conflict: %v", err)
	}
	defer func() {
		_ = conflictConn.Close()
	}()
	conflictAddr, ok := conflictConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected conflict addr type: %T", conflictConn.LocalAddr())
	}
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			Listen:      "127.0.0.1",
			ListenPort:  uint16(conflictAddr.Port),
			InboundTLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
	}
	startErr := ep.Start(adapter.StartStateStart)
	if startErr == nil {
		t.Fatal("expected Start to fail fast on listen udp conflict")
	}
	if ep.IsReady() {
		t.Fatal("server endpoint must remain not ready after listen conflict")
	}
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- ep.Close()
	}()
	select {
	case closeErr := <-closeDone:
		if closeErr != nil {
			t.Fatalf("close after listen conflict should stay safe, got: %v", closeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("close after listen conflict timed out (unexpected lifecycle hang)")
	}
	if _, listenErr := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(conflictAddr.Port))); listenErr == nil {
		t.Fatal("expected reserved conflict socket to keep the listen port busy during test")
	}
}

func TestServerEndpointStartNonStartStageNoOpThenRegularStartWorks(t *testing.T) {
	certPath, keyPath := writeServerTestCertificate(t)
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			Listen:      "127.0.0.1",
			ListenPort:  0,
			InboundTLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
	}
	if err := ep.Start(adapter.StartStateInitialize); err != nil {
		t.Fatalf("expected non-start stage to be no-op without error, got: %v", err)
	}
	if ep.IsReady() {
		t.Fatal("server endpoint must stay not ready after non-start stage no-op")
	}
	if ep.server != nil || ep.packetConn != nil || ep.tcpTLSListener != nil || ep.http2Server != nil {
		t.Fatal("non-start stage must not initialize server listener resources")
	}
	if err := ep.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("expected regular start after non-start stage no-op to succeed, got: %v", err)
	}
	if !ep.IsReady() {
		t.Fatal("server endpoint must become ready after regular Start")
	}
	if err := ep.Close(); err != nil {
		t.Fatalf("close after regular start failed: %v", err)
	}
}

func TestServerEndpointStartNonStartStagesAreIdempotentAndDoNotContaminateStartError(t *testing.T) {
	certPath, keyPath := writeServerTestCertificate(t)
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			Listen:      "127.0.0.1",
			ListenPort:  0,
			InboundTLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
	}
	ep.startErr.Store(net.ErrClosed)
	for _, stage := range []adapter.StartStage{
		adapter.StartStateInitialize,
		adapter.StartStatePostStart,
		adapter.StartStateStarted,
	} {
		if err := ep.Start(stage); err != nil {
			t.Fatalf("expected non-start stage %v to be no-op, got: %v", stage, err)
		}
	}
	if ep.server != nil || ep.packetConn != nil || ep.tcpTLSListener != nil || ep.http2Server != nil {
		t.Fatal("non-start stages must not initialize server listener resources")
	}
	if err := ep.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("expected regular start after repeated non-start stages to succeed, got: %v", err)
	}
	if !ep.IsReady() {
		t.Fatal("server endpoint must be ready after successful Start and stale startErr must be cleared")
	}
	if err := ep.Close(); err != nil {
		t.Fatalf("close after regular start failed: %v", err)
	}
}

func TestServerEndpointServeFailureThenRestartClearsStartErrorAndRestoresReady(t *testing.T) {
	certPath, keyPath := writeServerTestCertificate(t)
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			Listen:      "127.0.0.1",
			ListenPort:  0,
			InboundTLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
	}
	if err := ep.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("initial start failed: %v", err)
	}
	if !ep.IsReady() {
		t.Fatal("server must be ready after initial start")
	}
	if ep.packetConn == nil {
		t.Fatal("expected packetConn to be initialized after start")
	}
	_ = ep.packetConn.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if ep.lastStartError() != nil && !ep.IsReady() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ep.lastStartError() == nil {
		t.Fatal("expected serve failure to populate startErr after forced packetConn close")
	}
	if ep.IsReady() {
		t.Fatal("server must transition to not-ready after serve failure")
	}
	if err := ep.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close after serve failure failed: %v", err)
	}
	if err := ep.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("restart after serve failure failed: %v", err)
	}
	if !ep.IsReady() {
		t.Fatal("server must become ready after successful restart and stale startErr must be cleared")
	}
	if err := ep.Close(); err != nil {
		t.Fatalf("final close failed: %v", err)
	}
}

func TestServerEndpointConcurrentCloseDoesNotPoisonStartError(t *testing.T) {
	certPath, keyPath := writeServerTestCertificate(t)
	ep := &ServerEndpoint{
		options: option.MasqueEndpointOptions{
			Listen:      "127.0.0.1",
			ListenPort:  0,
			InboundTLS: &option.InboundTLSOptions{
				Enabled:         true,
				CertificatePath: certPath,
				KeyPath:         keyPath,
			},
		},
	}
	if err := ep.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	if !ep.IsReady() {
		t.Fatal("server must be ready after start")
	}
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- ep.Close()
	}()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("close failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close timed out")
	}
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if ep.lastStartError() != nil {
			t.Fatalf("expected no fatal startErr on normal shutdown, got: %v", ep.lastStartError())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ep.IsReady() {
		t.Fatal("server must remain not-ready after close")
	}
}

func writeServerTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatalf("generate cert serial: %v", err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "masque-test.local",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"masque-test.local", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func makeConnectIPTestRequest(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodConnect, rawURL, nil)
	if err != nil {
		t.Fatalf("new connect-ip request: %v", err)
	}
	req.Proto = "connect-ip"
	req.Host = "localhost:1234"
	req.Header.Set("Capsule-Protocol", "?1")
	return req
}

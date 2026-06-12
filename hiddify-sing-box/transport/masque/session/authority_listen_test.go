package session

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"
)

func testAuthorityListenTLSCert(t *testing.T) *tls.Config {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "masque-authority-listen-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
}

func TestAuthorityHTTPServerStartCloseServe(t *testing.T) {
	t.Parallel()
	serveEnd := make(chan struct{})
	as, err := StartAuthorityHTTPServer(AuthorityListenOptions{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  testAuthorityListenTLSCert(t),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}),
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if as == nil || as.Server == nil || as.PacketConn == nil {
		t.Fatal("expected non-nil authority server stack")
	}
	if as.Server.QUICConfig == nil || as.Server.QUICConfig.EnableDatagrams {
		t.Fatal("expected authority QUIC config without datagram plane")
	}
	go func() {
		_ = as.Serve()
		close(serveEnd)
	}()
	if err := as.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-serveEnd:
	case <-time.After(5 * time.Second):
		t.Fatal("serve goroutine did not finish after close")
	}
}

func TestAuthorityHTTPServerInvalidListenAddr(t *testing.T) {
	t.Parallel()
	_, err := StartAuthorityHTTPServer(AuthorityListenOptions{
		ListenAddr: "not-a-valid-udp-addr",
		TLSConfig:  testAuthorityListenTLSCert(t),
		Handler:    http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	})
	if err == nil {
		t.Fatal("expected error for invalid listen address")
	}
}

func TestAuthorityHTTPServerNilServeClose(t *testing.T) {
	t.Parallel()
	var as *AuthorityHTTPServer
	if err := as.Serve(); err != nil {
		t.Fatalf("nil serve: %v", err)
	}
	if err := as.Close(); err != nil {
		t.Fatalf("nil close: %v", err)
	}
}

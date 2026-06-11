package tls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// Ensures inbound STD TLS (certificate_path) accepts a stock crypto/tls client like Xray/Happ.
func TestSTDServerAcceptsStdTLSClient(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, "masque.ai-qwerty.ru")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx := context.Background()
	logger := log.NewNOPFactory().NewLogger("test")
	srvCfg, err := boxtls.NewServer(ctx, logger, option.InboundTLSOptions{
		Enabled:         true,
		ServerName:      "masque.ai-qwerty.ru",
		ALPN:            []string{"h2", "http/1.1"},
		MinVersion:      "1.2",
		Certificate:     []string{string(certPEM)},
		Key:             []string{string(keyPEM)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srvCfg.Start(); err != nil {
		t.Fatal(err)
	}
	defer srvCfg.Close()

	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = boxtls.ServerHandshake(ctx, raw, srvCfg)
	}()

	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rawClient.Close()

	client := tls.Client(rawClient, &tls.Config{
		ServerName:         "masque.ai-qwerty.ru",
		NextProtos:         []string{"h2"},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // test cert is self-signed; client stack matches Xray/Happ TLS negotiation
	})
	if err := client.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("std tls client handshake: %v", err)
	}
	state := client.ConnectionState()
	if !state.HandshakeComplete {
		t.Fatal("handshake not complete")
	}
	if state.ServerName != "masque.ai-qwerty.ru" {
		t.Fatalf("unexpected SNI in state: %q", state.ServerName)
	}
}

func generateTestCert(t *testing.T, serverName string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{serverName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	return certPEM, keyPEM
}

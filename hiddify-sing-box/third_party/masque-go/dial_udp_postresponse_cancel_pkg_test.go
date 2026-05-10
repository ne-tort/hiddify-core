package masque

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

var (
	dialPostResponseMasquePkgTLS  *tls.Config
	dialPostResponseMasquePkgPool *x509.CertPool
)

func init() {
	dialPostResponseMasquePkgTLS, dialPostResponseMasquePkgPool = mustSelfSignedLoopbackTLS()
}

func mustSelfSignedLoopbackTLS() (*tls.Config, *x509.CertPool) {
	caTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
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
		panic(err)
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTempl, caTempl, &caKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	ca, err := x509.ParseCertificate(caBytes)
	if err != nil {
		panic(err)
	}

	leafTempl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTempl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafBytes},
			PrivateKey:  leafKey,
		}},
		NextProtos: []string{http3.NextProtoH3},
	}
	return serverTLS, pool
}

func runEchoUDPListener(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, raddr, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := c.WriteTo(buf[:n], raddr); err != nil {
				return
			}
		}
	}()
	return c
}

func TestDialAddrReturnsCauseWhenCanceledAfterSuccessfulCONNECTUDPResponse(t *testing.T) {
	remoteEcho := runEchoUDPListener(t)
	quicConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = quicConn.Close() })
	port := quicConn.LocalAddr().(*net.UDPAddr).Port
	template := uritemplate.MustNew(fmt.Sprintf("https://localhost:%d/masque?h={target_host}&p={target_port}", port))

	mux := http.NewServeMux()
	server := http3.Server{
		TLSConfig:       dialPostResponseMasquePkgTLS,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: true,
		Handler:         mux,
	}
	t.Cleanup(func() { _ = server.Close() })
	proxy := Proxy{}
	t.Cleanup(func() { _ = proxy.Close() })
	mux.HandleFunc("/masque", func(w http.ResponseWriter, r *http.Request) {
		req, err := ParseRequest(r, template)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		req.Target = remoteEcho.LocalAddr().String()
		_ = proxy.Proxy(w, req)
	})
	go func() {
		_ = server.Serve(quicConn)
	}()

	cl := Client{
		TLSClientConfig: &tls.Config{
			RootCAs:    dialPostResponseMasquePkgPool,
			ServerName: "localhost",
			NextProtos: []string{http3.NextProtoH3},
		},
	}
	defer func() { _ = cl.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var once sync.Once
	prev := dialUDPTestAfterSuccessfulCONNECTResponse
	dialUDPTestAfterSuccessfulCONNECTResponse = func(context.Context) {
		once.Do(cancel)
	}
	defer func() { dialUDPTestAfterSuccessfulCONNECTResponse = prev }()

	_, _, dialErr := cl.DialAddr(ctx, template, "127.0.0.1:9") // rewritten on server like connect-udp tests
	require.ErrorIs(t, dialErr, context.Canceled)
}

package h2

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSynth_MasqueTCPDialTLS_NotBypassed proves H2 transport uses the hook (BuildTCPDialTLS path)
// instead of falling back to tls.Client(conn, TLSConfig). Distinctive SNI only exists in the hook.
func TestSynth_MasqueTCPDialTLS_NotBypassed(t *testing.T) {
	t.Parallel()
	const (
		hookSNI = "hook-sni.example.com"
		cfgSNI  = "config-sni.example.com"
	)
	cert := mustSelfSigned(t, hookSNI)

	var seenSNI atomic.Value
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	serverErr := make(chan error, 1)
	go func() {
		cfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2"},
			MinVersion:   tls.VersionTLS12,
			GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				seenSNI.Store(chi.ServerName)
				return nil, nil
			},
		}
		srv := tls.Server(serverRaw, cfg)
		err := srv.Handshake()
		_ = srv.Close()
		serverErr <- err
	}()

	var hookCalls atomic.Int32
	tr, err := NewClientTransport(ClientDialConfig{
		// TLSConfig deliberately has WRONG SNI — if fallback tls.Client were used, server would see cfgSNI.
		TLSConfig: &tls.Config{
			ServerName:         cfgSNI,
			NextProtos:         []string{"h2"},
			InsecureSkipVerify: true,
		},
		DialHostCandidates: []string{""},
		TCPDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return clientRaw, nil
		},
		MasqueTCPDialTLS: func(ctx context.Context, conn net.Conn, nextProtos []string, addr string) (net.Conn, error) {
			hookCalls.Add(1)
			cfg := &tls.Config{
				ServerName:         hookSNI,
				NextProtos:         nextProtos,
				InsecureSkipVerify: true,
			}
			c := tls.Client(conn, cfg)
			if err := c.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			return c, nil
		},
	})
	require.NoError(t, err)

	// Drive DialTLSContext once. Cancel soon after hook fires so we don't wait for HTTP/2 preface.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		for i := 0; i < 50; i++ {
			if hookCalls.Load() > 0 && seenSNI.Load() != nil {
				cancel()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	conn, err := tr.DialTLSContext(ctx, "tcp", "127.0.0.1:443", tr.TLSClientConfig)
	if conn != nil {
		_ = conn.Close()
	}
	_ = err

	require.Equal(t, int32(1), hookCalls.Load(), "MasqueTCPDialTLS hook must be invoked (not tls.Client bypass)")
	got, _ := seenSNI.Load().(string)
	require.Equal(t, hookSNI, got, "server must see hook SNI, proving tls.Client(TLSConfig) path was not used")

	select {
	case <-serverErr:
	case <-time.After(2 * time.Second):
	}
}

func TestSynth_MasqueTCPDialTLSNil_FallsBackToTLSConfig(t *testing.T) {
	t.Parallel()
	const cfgSNI = "fallback-sni.example.com"
	cert := mustSelfSigned(t, cfgSNI)

	var seenSNI atomic.Value
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		cfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2"},
			MinVersion:   tls.VersionTLS12,
			GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				seenSNI.Store(chi.ServerName)
				return nil, nil
			},
		}
		srv := tls.Server(serverRaw, cfg)
		_ = srv.Handshake()
		_ = srv.Close()
	}()

	tr, err := NewClientTransport(ClientDialConfig{
		TLSConfig: &tls.Config{
			ServerName:         cfgSNI,
			NextProtos:         []string{"h2"},
			InsecureSkipVerify: true,
		},
		DialHostCandidates: []string{""},
		TCPDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return clientRaw, nil
		},
		// MasqueTCPDialTLS nil → tls.Client(conn, tlsCfg) fallback
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		for i := 0; i < 50; i++ {
			if seenSNI.Load() != nil {
				cancel()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	conn, _ := tr.DialTLSContext(ctx, "tcp", "127.0.0.1:443", tr.TLSClientConfig)
	if conn != nil {
		_ = conn.Close()
	}

	got, _ := seenSNI.Load().(string)
	require.Equal(t, cfgSNI, got, "nil hook must use TLSConfig.ServerName")
	<-done
}

func mustSelfSigned(t *testing.T, host string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return c
}

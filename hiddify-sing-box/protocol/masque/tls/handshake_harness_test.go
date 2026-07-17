package masquetls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testTLSHost = "wiki.example.com"

type captureConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (c *captureConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), b...))
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *captureConn) snapshot() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.writes))
	for i := range c.writes {
		out[i] = append([]byte(nil), c.writes[i]...)
	}
	return out
}

func (c *captureConn) joined() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var n int
	for _, w := range c.writes {
		n += len(w)
	}
	out := make([]byte, 0, n)
	for _, w := range c.writes {
		out = append(out, w...)
	}
	return out
}

func countTLSRecords(payload []byte) int {
	n := 0
	i := 0
	for i+5 <= len(payload) {
		if payload[i] != 0x16 && payload[i] != 0x17 && payload[i] != 0x15 && payload[i] != 0x14 {
			break
		}
		recLen := int(binary.BigEndian.Uint16(payload[i+3 : i+5]))
		if recLen < 0 || i+5+recLen > len(payload) {
			break
		}
		n++
		i += 5 + recLen
	}
	return n
}

func generateTestTLSMaterial(t *testing.T, host string) (tls.Certificate, []string /*certPEM lines*/, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(certPEM))
	return tlsCert, []string{string(certPEM)}, pool
}

type helloCapture struct {
	mu    sync.Mutex
	hello *tls.ClientHelloInfo
}

func (h *helloCapture) set(chi *tls.ClientHelloInfo) {
	h.mu.Lock()
	defer h.mu.Unlock()
	cp := *chi
	if chi.SupportedProtos != nil {
		cp.SupportedProtos = append([]string(nil), chi.SupportedProtos...)
	}
	h.hello = &cp
}

func (h *helloCapture) get() *tls.ClientHelloInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hello
}

// startPipeTLSServer runs tls.Server on one end of net.Pipe; returns the client raw half.
func startPipeTLSServer(t *testing.T, serverTLS *tls.Config, hello *helloCapture) (clientRaw net.Conn, serverDone <-chan error) {
	t.Helper()
	clientRaw, serverRaw := net.Pipe()
	cfg := serverTLS.Clone()
	if hello != nil {
		prev := cfg.GetConfigForClient
		cfg.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			hello.set(chi)
			if prev != nil {
				return prev(chi)
			}
			return nil, nil
		}
	}
	done := make(chan error, 1)
	go func() {
		srv := tls.Server(serverRaw, cfg)
		err := srv.Handshake()
		if err != nil {
			_ = serverRaw.Close()
			done <- err
			return
		}
		buf := make([]byte, 1)
		_, _ = srv.Read(buf) // wait briefly for client close / half
		_ = srv.Close()
		done <- nil
	}()
	t.Cleanup(func() {
		_ = clientRaw.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	return clientRaw, done
}

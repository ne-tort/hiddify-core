package h2

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	_ "github.com/sagernet/sing-box/internal/http2xconnect"
	"github.com/sagernet/sing-box/transport/masque/connectudp/split"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

var h2IntegrationTestTLS *tls.Config

func init() {
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
		panic("h2_integration_test: generate CA key: " + err.Error())
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTempl, caTempl, &caKey.PublicKey, caKey)
	if err != nil {
		panic("h2_integration_test: create CA cert: " + err.Error())
	}
	ca, err := x509.ParseCertificate(caBytes)
	if err != nil {
		panic("h2_integration_test: parse CA: " + err.Error())
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
		panic("h2_integration_test: generate leaf key: " + err.Error())
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTempl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		panic("h2_integration_test: create leaf: " + err.Error())
	}
	if _, err := x509.ParseCertificate(leafBytes); err != nil {
		panic("h2_integration_test: parse leaf: " + err.Error())
	}

	h2IntegrationTestTLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafBytes},
			PrivateKey:  leafKey,
		}},
		NextProtos: []string{http2.NextProtoTLS, "http/1.1"},
	}
}

func runH2IntegrationUDPEcho(t *testing.T, addr *net.UDPAddr) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", addr)
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

func startInProcessH2UDPConnectProxy(t *testing.T) int {
	t.Helper()
	return StartInProcessConnectUDPProxy(t, h2IntegrationTestTLS, NewSessionRegistry())
}

func newH2IntegrationDialConfig(t *testing.T, proxyPort int) H2OverlayDialConfig {
	t.Helper()
	clientTLS := h2IntegrationTestTLS.Clone()
	clientTLS.InsecureSkipVerify = true
	clientTLS.ServerName = "127.0.0.1"
	tr, err := h2c.NewClientTransport(h2c.ClientDialConfig{
		TLSConfig: clientTLS,
		DialHostCandidates: []string{""},
		TCPDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	})
	require.NoError(t, err)
	return H2OverlayDialConfig{
		EnsureTransport: func(context.Context) (*http2.Transport, error) {
			return tr, nil
		},
		ResolveDialAddr: func() string {
			return net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort))
		},
	}
}

// newH2ProdShapedIntegrationDialConfig adds NewTransport like core_session.dialUDPOverHTTP2 (UDP-AUDIT-10).
func newH2ProdShapedIntegrationDialConfig(t *testing.T, proxyPort int) H2OverlayDialConfig {
	t.Helper()
	cfg := newH2IntegrationDialConfig(t, proxyPort)
	clientTLS := h2IntegrationTestTLS.Clone()
	clientTLS.InsecureSkipVerify = true
	clientTLS.ServerName = "127.0.0.1"
	dialCfg := h2c.ClientDialConfig{
		TLSConfig:          clientTLS,
		DialHostCandidates: []string{""},
		TCPDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	cfg.NewTransport = func() (*http2.Transport, error) {
		return h2c.NewClientTransport(dialCfg)
	}
	return cfg
}

func dialH2IntegrationUDPWithConfig(t *testing.T, proxyPort int, cfg H2OverlayDialConfig, target string) net.PacketConn {
	t.Helper()
	rawTpl := "https://127.0.0.1:" + strconv.Itoa(proxyPort) + "/masque/udp/{target_host}/{target_port}/"
	tpl, err := uritemplate.New(rawTpl)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)

	pc, err := DialH2Overlay(ctx, cfg, tpl, target)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

func dialH2IntegrationUDP(t *testing.T, proxyPort int, target string) net.PacketConn {
	return dialH2IntegrationUDPWithConfig(t, proxyPort, newH2IntegrationDialConfig(t, proxyPort), target)
}

func TestH2ConnectUDPEchoRoundTripInProcess(t *testing.T) {
	echo := runH2IntegrationUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	proxyPort := startInProcessH2UDPConnectProxy(t)
	pc := dialH2IntegrationUDP(t, proxyPort, net.JoinHostPort("127.0.0.1", strconv.Itoa(echoPort)))

	payload := []byte("ping-h2-udp-echo")
	nw, err := pc.WriteTo(payload, nil)
	require.NoError(t, err)
	require.Equal(t, len(payload), nw)

	buf := make([]byte, 256)
	nr, _, err := pc.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, payload, buf[:nr])
}

// TestH2ConnectUDPEchoProdShapedNewTransport exercises asymmetric dial with NewTransport (prod core_session parity).
func TestH2ConnectUDPEchoProdShapedNewTransport(t *testing.T) {
	t.Setenv("MASQUE_H2_CONNECT_UDP_ASYMMETRIC_DUPLEX", "1")
	echo := runH2IntegrationUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	proxyPort := startInProcessH2UDPConnectProxy(t)
	cfg := newH2ProdShapedIntegrationDialConfig(t, proxyPort)
	pc := dialH2IntegrationUDPWithConfig(t, proxyPort, cfg, net.JoinHostPort("127.0.0.1", strconv.Itoa(echoPort)))

	payload := []byte("ping-h2-udp-echo-prod-shaped")
	nw, err := pc.WriteTo(payload, nil)
	require.NoError(t, err)
	require.Equal(t, len(payload), nw)

	buf := make([]byte, 256)
	nr, _, err := pc.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, payload, buf[:nr])
}

func TestH2ConnectUDPPortUnreachableRoundTripInProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("connected UDP ICMP port-unreachable is unreliable on Windows; bench runs on Linux")
	}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = tcpLn.Close() })
	tcpPort := tcpLn.Addr().(*net.TCPAddr).Port

	proxyPort := startInProcessH2UDPConnectProxy(t)
	pc := dialH2IntegrationUDP(t, proxyPort, net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpPort)))

	_, err = pc.WriteTo([]byte{0x00, 0x01, 0x02}, nil)
	require.NoError(t, err)

	buf := make([]byte, 256)
	n, _, err := pc.ReadFrom(buf)
	require.Equal(t, 0, n)
	require.ErrorIs(t, err, split.ErrPortUnreachable)
}

func TestH2ConnectUDPReadBeforeWriteMatchesTUNOrder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("connected UDP ICMP port-unreachable is unreliable on Windows")
	}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = tcpLn.Close() })
	tcpPort := tcpLn.Addr().(*net.TCPAddr).Port

	proxyPort := startInProcessH2UDPConnectProxy(t)
	inner := dialH2IntegrationUDP(t, proxyPort, net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpPort)))
	pc := split.NewDatagramSplitConn(inner, split.DatagramSplitOptions{
		MaxPayload: 1200,
		MapICMP: func(addr net.Addr, err error) error {
			return split.NewPortUnreachableError(addr)
		},
	})

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 512)
		n, _, rerr := pc.ReadFrom(buf)
		if rerr != nil {
			errCh <- rerr
			return
		}
		if n != 0 {
			errCh <- fmt.Errorf("expected icmp empty read, got %d bytes", n)
			return
		}
		errCh <- nil
	}()
	time.Sleep(30 * time.Millisecond)
	dnsLike := bytes.Repeat([]byte{0xab}, 40)
	_, werr := pc.WriteTo(dnsLike, nil)
	require.NoError(t, werr)
	select {
	case rerr := <-errCh:
		require.ErrorIs(t, rerr, split.ErrPortUnreachable)
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFrom blocked past upload (TUN order deadlock)")
	}
}

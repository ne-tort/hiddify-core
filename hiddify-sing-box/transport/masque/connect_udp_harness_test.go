package masque

// Tests here exercise the real client CONNECT-UDP path (ListenPacket → masque/quic-go stack) against an
// in-process HTTP/3 MASQUE proxy and a local UDP echo. No Docker/VPN/WAN — failures point to fork code or
// harness, not internet/iperf firewall. For end-to-end UDP through VPN see bench/run-bench-report.sh UDP probe.

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
	"net/netip"
	"testing"
	"time"

	qmasque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

// connectUDPTestTLS is a shared leaf cert (localhost + 127.0.0.1) for in-process HTTP/3 MASQUE proxy tests.
var connectUDPTestTLS *tls.Config

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
		panic("connect_udp_harness_test: generate CA key: " + err.Error())
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTempl, caTempl, &caKey.PublicKey, caKey)
	if err != nil {
		panic("connect_udp_harness_test: create CA cert: " + err.Error())
	}
	ca, err := x509.ParseCertificate(caBytes)
	if err != nil {
		panic("connect_udp_harness_test: parse CA: " + err.Error())
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
		panic("connect_udp_harness_test: generate leaf key: " + err.Error())
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTempl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		panic("connect_udp_harness_test: create leaf: " + err.Error())
	}
	if _, err := x509.ParseCertificate(leafBytes); err != nil {
		panic("connect_udp_harness_test: parse leaf: " + err.Error())
	}

	connectUDPTestTLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafBytes},
			PrivateKey:  leafKey,
		}},
		NextProtos: []string{http3.NextProtoH3},
	}
}

func runUDPEcho(t *testing.T, addr *net.UDPAddr) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen echo udp: %v", err)
	}
	t.Cleanup(func() { c.Close() })
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

// startInProcessMasqueUDPProxy serves HTTP/3 on an ephemeral UDP port. register must add handlers
// (typically /masque/udp/{target_host}/{target_port}) and own proxy-side Close hooks via t.Cleanup.
func startInProcessMasqueUDPProxy(t *testing.T, register func(mux *http.ServeMux, proxyPort int)) int {
	t.Helper()
	quicConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen quic udp: %v", err)
	}
	t.Cleanup(func() { quicConn.Close() })
	proxyPort := quicConn.LocalAddr().(*net.UDPAddr).Port

	mux := http.NewServeMux()
	register(mux, proxyPort)
	server := http3.Server{
		TLSConfig:       connectUDPTestTLS,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: true,
		Handler:         mux,
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(quicConn) }()
	time.Sleep(20 * time.Millisecond)
	return proxyPort
}

// TestCoreSessionConnectUDPEchoInProcess exercises ListenPacket CONNECT-UDP path (masqueUDP split wrapper +
// vendor masque.Client) against a local HTTP/3 CONNECT-UDP proxy, without docker compose.
func TestCoreSessionConnectUDPEchoInProcess(t *testing.T) {
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		templateRaw := fmt.Sprintf("https://127.0.0.1:%d/masque/udp/{target_host}/{target_port}", proxyPort)
		udpTemplate, err := uritemplate.New(templateRaw)
		if err != nil {
			t.Fatalf("udp template: %v", err)
		}
		var udpProxy qmasque.Proxy
		t.Cleanup(func() { _ = udpProxy.Close() })
		mux.HandleFunc("/masque/udp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
			req, err := qmasque.ParseRequest(r, udpTemplate)
			if err != nil {
				if pe, ok := err.(*qmasque.RequestParseError); ok {
					w.WriteHeader(pe.HTTPStatus)
					return
				}
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if err := udpProxy.Proxy(w, req); err != nil {
				w.WriteHeader(http.StatusBadGateway)
			}
		})
	})

	waitCtx2, cancel2 := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel2()

	session, err := (CoreClientFactory{}).NewSession(waitCtx2, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer func() { _ = session.Close() }()

	pkt, err := session.ListenPacket(waitCtx2, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("listenpacket connect-udp: %v", err)
	}
	defer func() { _ = pkt.Close() }()

	payload := []byte("masque-udp-harness-echo-ping")
	dest := echoAddr

	if err := pkt.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if err := pkt.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}

	if _, err := pkt.WriteTo(payload, dest); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2048)
	n, addr, err := pkt.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf[:n], payload)
	}
	udpBack, ok := addr.(*net.UDPAddr)
	if !ok || !udpBack.IP.Equal(echoAddr.IP) || udpBack.Port != echoAddr.Port {
		t.Fatalf("unexpected source addr %v want %v", addr, echoAddr)
	}
}

// TestCoreSessionConnectUDPSplitPayloadEchoInProcess verifies masqueUDPDatagramSplitConn splits a large
// WriteTo (> masqueUDPWriteMax) across datagrams; echo sends fragments back as separate UDP packets.
func TestCoreSessionConnectUDPSplitPayloadEchoInProcess(t *testing.T) {
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		templateRaw := fmt.Sprintf("https://127.0.0.1:%d/masque/udp/{target_host}/{target_port}", proxyPort)
		udpTemplate, err := uritemplate.New(templateRaw)
		if err != nil {
			t.Fatalf("udp template: %v", err)
		}
		var udpProxy qmasque.Proxy
		t.Cleanup(func() { _ = udpProxy.Close() })
		mux.HandleFunc("/masque/udp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
			req, err := qmasque.ParseRequest(r, udpTemplate)
			if err != nil {
				if pe, ok := err.(*qmasque.RequestParseError); ok {
					w.WriteHeader(pe.HTTPStatus)
					return
				}
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if err := udpProxy.Proxy(w, req); err != nil {
				w.WriteHeader(http.StatusBadGateway)
			}
		})
	})

	waitCtx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer func() { _ = session.Close() }()

	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("listenpacket connect-udp: %v", err)
	}
	defer func() { _ = pkt.Close() }()

	wantLen := 2500
	payload := make([]byte, wantLen)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	dest := echoAddr

	deadline := time.Now().Add(4 * time.Second)
	if err := pkt.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if err := pkt.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}

	nWr, err := pkt.WriteTo(payload, dest)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if nWr != wantLen {
		t.Fatalf("short write: %d want %d", nWr, wantLen)
	}

	got := make([]byte, 0, wantLen)
	buf := make([]byte, 2048)
	for len(got) < wantLen {
		n, addr, err := pkt.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read: %v (got %d bytes)", err, len(got))
		}
		udpBack, ok := addr.(*net.UDPAddr)
		if !ok || !udpBack.IP.Equal(echoAddr.IP) || udpBack.Port != echoAddr.Port {
			t.Fatalf("unexpected source addr %v want %v", addr, echoAddr)
		}
		got = append(got, buf[:n]...)
	}
	if string(got) != string(payload) {
		t.Fatalf("split echo mismatch (len got=%d want=%d)", len(got), wantLen)
	}
}

// TestCoreSessionConnectUDPForbiddenBeforeProxy rejects CONNECT-UDP setup when proxy returns HTTP 403.
func TestCoreSessionConnectUDPForbiddenBeforeProxy(t *testing.T) {
	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		templateRaw := fmt.Sprintf("https://127.0.0.1:%d/masque/udp/{target_host}/{target_port}", proxyPort)
		udpTemplate, err := uritemplate.New(templateRaw)
		if err != nil {
			t.Fatalf("udp template: %v", err)
		}
		var udpProxy qmasque.Proxy
		t.Cleanup(func() { _ = udpProxy.Close() })
		mux.HandleFunc("/masque/udp/{target_host}/{target_port}", func(w http.ResponseWriter, r *http.Request) {
			if _, err := qmasque.ParseRequest(r, udpTemplate); err != nil {
				if pe, ok := err.(*qmasque.RequestParseError); ok {
					w.WriteHeader(pe.HTTPStatus)
					return
				}
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusForbidden)
		})
	})

	waitCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer func() { _ = session.Close() }()

	_, err = session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr("127.0.0.1"),
		Port: 9,
	})
	if err == nil {
		t.Fatal("expected ListenPacket to fail when proxy responds 403")
	}
}

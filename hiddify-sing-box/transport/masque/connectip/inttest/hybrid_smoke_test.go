package inttest_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing-box/transport/masque/connectip/inttest"
	M "github.com/sagernet/sing/common/metadata"
)

// TestConnectIPHybridConnectStreamH3Smoke exercises prod connect-ip-h3 hybrid profile in-proc:
// transport_mode=connect_ip (OpenIPSession) + tcp_transport=connect_stream (DialContext TCP leg).
func TestConnectIPHybridConnectStreamH3Smoke(t *testing.T) {
	echoLn := inttest.StartHybridConnectIPEchoTarget(t)
	downLn := inttest.StartHybridConnectIPDownloadTarget(t)
	proxyPort := inttest.StartHybridConnectIPH3Server(t)

	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session, err := (masque.CoreClientFactory{}).NewSession(waitCtx, inttest.HybridConnectStreamH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("new hybrid session: %v", err)
	}
	defer session.Close()

	caps := session.Capabilities()
	if !caps.ConnectIP {
		t.Fatal("expected ConnectIP capability on hybrid session")
	}
	if !caps.ConnectTCP {
		t.Fatal("expected ConnectTCP capability on hybrid connect_ip+connect_stream session")
	}

	ipSess, err := session.OpenIPSession(waitCtx)
	if err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}
	if ipSess == nil {
		t.Fatal("expected non-nil CONNECT-IP packet session")
	}

	echoPort := uint16(echoLn.Addr().(*net.TCPAddr).Port)
	echoConn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", echoPort))
	if err != nil {
		t.Fatalf("DialContext tcp (connect_stream leg): %v", err)
	}
	defer echoConn.Close()

	payload := []byte(inttest.HybridSmokeEchoPayload)
	if _, err := echoConn.Write(payload); err != nil {
		t.Fatalf("write echo: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(echoConn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("DialContext download: %v", err)
	}
	defer downConn.Close()

	n, mbps, err := inttest.MeasureHybridSmokeDownloadWriteToMbps(downConn, inttest.HybridSmokeBenchDur)
	if err != nil {
		t.Fatalf("download WriteTo: %v", err)
	}
	t.Logf("connect-ip-h3 hybrid download sanity: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < inttest.HybridSmokeMinDownMbps && n < inttest.HybridSmokeMinBytes {
		t.Fatalf("hybrid download too slow: %.1f Mbit/s %d bytes (want >= %.0f Mbit/s or >= %d bytes)",
			mbps, n, inttest.HybridSmokeMinDownMbps, inttest.HybridSmokeMinBytes)
	}
}

// TestConnectIPHybridConnectStreamH2Smoke exercises prod connect-ip-h2 hybrid profile in-proc:
// transport_mode=connect_ip (OpenIPSession) + tcp_transport=connect_stream over HTTP/2.
func TestConnectIPHybridConnectStreamH2Smoke(t *testing.T) {
	echoLn := inttest.StartHybridConnectIPEchoTarget(t)
	downLn := inttest.StartHybridConnectIPDownloadTarget(t)
	proxyPort := inttest.StartHybridConnectIPH2Server(t)

	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	session, err := (masque.CoreClientFactory{}).NewSession(waitCtx, masque.ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(proxyPort),
		MasqueQUICCryptoTLS:      &tls.Config{InsecureSkipVerify: true},
		TransportMode:            "connect_ip",
		TCPTransport:             "connect_stream",
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
		TCPDial:                  baseDial,
	})
	if err != nil {
		t.Fatalf("new hybrid h2 session: %v", err)
	}
	defer session.Close()

	caps := session.Capabilities()
	if !caps.ConnectIP {
		t.Fatal("expected ConnectIP capability on hybrid h2 session")
	}
	if !caps.ConnectTCP {
		t.Fatal("expected ConnectTCP capability on hybrid connect_ip+connect_stream h2 session")
	}

	ipSess, err := session.OpenIPSession(waitCtx)
	if err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}
	if ipSess == nil {
		t.Fatal("expected non-nil CONNECT-IP packet session on h2")
	}

	echoPort := uint16(echoLn.Addr().(*net.TCPAddr).Port)
	echoConn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", echoPort))
	if err != nil {
		t.Fatalf("DialContext tcp (connect_stream h2 leg): %v", err)
	}
	defer echoConn.Close()

	payload := []byte(inttest.HybridSmokeEchoPayload)
	if _, err := echoConn.Write(payload); err != nil {
		t.Fatalf("write echo: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(echoConn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("DialContext download: %v", err)
	}
	defer downConn.Close()

	n, mbps, err := inttest.MeasureHybridSmokeDownloadWriteToMbps(downConn, inttest.HybridSmokeBenchDur)
	if err != nil {
		t.Fatalf("download WriteTo: %v", err)
	}
	t.Logf("connect-ip-h2 hybrid download sanity: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < inttest.HybridSmokeMinDownMbps && n < inttest.HybridSmokeMinBytes {
		t.Fatalf("hybrid h2 download too slow: %.1f Mbit/s %d bytes (want >= %.0f Mbit/s or >= %d bytes)",
			mbps, n, inttest.HybridSmokeMinDownMbps, inttest.HybridSmokeMinBytes)
	}
}

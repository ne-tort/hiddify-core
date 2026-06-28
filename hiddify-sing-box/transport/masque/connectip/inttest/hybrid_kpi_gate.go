package inttest

// Hybrid connect_ip + connect_stream download KPI gates (W-IP-9 IP-9-PR0).

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

// RunConnectIPHybridConnectStreamH2DownloadKPI gates connect_ip + connect_stream H2 download WriteTo.
func RunConnectIPHybridConnectStreamH2DownloadKPI(t *testing.T) {
	t.Helper()
	downLn := StartHybridConnectIPDownloadTarget(t)
	proxyPort := StartHybridConnectIPH2Server(t)

	waitCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	session, err := (masque.CoreClientFactory{}).NewSession(waitCtx, HybridConnectStreamH2ClientOptions(proxyPort, baseDial))
	if err != nil {
		t.Fatalf("new hybrid h2 session: %v", err)
	}
	defer session.Close()

	if _, err := session.OpenIPSession(waitCtx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("DialContext download: %v", err)
	}
	defer downConn.Close()

	n, mbps, err := MeasureHybridSmokeDownloadWriteToMbps(downConn, HybridSynthBenchDur)
	if err != nil && n == 0 {
		t.Fatalf("connect-ip-h2 download WriteTo: %v", err)
	}
	t.Logf("connect-ip-h2 hybrid download KPI: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < masque.ExportConnectStreamSynthProdMinMbps {
		t.Fatalf("%s", masque.SynthKPIDiagnostic("[connect-ip-h2 L3 hybrid]", "tcp_down WriteTo", mbps,
			masque.ExportConnectStreamSynthProdMinMbps,
			"connect_ip packet plane + H2 connect_stream TCP leg"))
	}
}

// RunConnectIPHybridConnectStreamH3DownloadKPI gates connect_ip + connect_stream H3 download WriteTo.
func RunConnectIPHybridConnectStreamH3DownloadKPI(t *testing.T) {
	t.Helper()
	downLn := StartHybridConnectIPDownloadTarget(t)
	proxyPort := StartHybridConnectIPH3Server(t)

	waitCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	session, err := (masque.CoreClientFactory{}).NewSession(waitCtx, HybridConnectStreamH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("new hybrid h3 session: %v", err)
	}
	defer session.Close()

	if _, err := session.OpenIPSession(waitCtx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("DialContext download: %v", err)
	}
	defer downConn.Close()

	n, mbps, err := MeasureHybridSmokeDownloadWriteToMbps(downConn, HybridSynthBenchDur)
	if err != nil && n == 0 {
		t.Fatalf("connect-ip-h3 download WriteTo: %v", err)
	}
	t.Logf("connect-ip-h3 hybrid download KPI: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < masque.ExportConnectStreamSynthProdMinMbps {
		t.Fatalf("%s", masque.SynthKPIDiagnostic("[connect-ip-h3 L3 hybrid]", "tcp_down WriteTo", mbps,
			masque.ExportConnectStreamSynthProdMinMbps,
			"connect_ip packet plane + H3 connect_stream TCP leg"))
	}
}

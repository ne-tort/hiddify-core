package masque_test

// REF connect-ip differential: hybrid connect_ip+connect_stream vs pure connect_stream (B1).

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing-box/transport/masque/connectip/inttest"
	M "github.com/sagernet/sing/common/metadata"
)

func measurePureConnectStreamH3DownloadMbps(t *testing.T) float64 {
	t.Helper()
	dur := masque.ExportConnectStreamSynthProdBenchDuration
	targetPort := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)
	_, mbps := measureProdStackDownloadMbps(t, socksPort, targetPort, dur)
	return mbps
}

func measureHybridConnectIPH3DownloadMbps(t *testing.T) float64 {
	t.Helper()
	downLn := inttest.StartHybridConnectIPDownloadTarget(t)
	proxyPort := inttest.StartHybridConnectIPH3Server(t)

	waitCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	session, err := (masque.CoreClientFactory{}).NewSession(waitCtx, masque.ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TransportMode:       "connect_ip",
		TCPTransport:        "connect_stream",
	})
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

	_, mbps, err := inttest.MeasureHybridSmokeDownloadWriteToMbps(downConn, inttest.HybridSynthBenchDur)
	if err != nil {
		t.Fatalf("hybrid WriteTo: %v", err)
	}
	return mbps
}

// TestREFConnectIPDeltaVsPureStream logs Δ Mbps hybrid vs pure connect_stream H3 on one bulk target.
func TestREFConnectIPDeltaVsPureStream(t *testing.T) {
	pure := measurePureConnectStreamH3DownloadMbps(t)
	hybrid := measureHybridConnectIPH3DownloadMbps(t)
	delta := hybrid - pure
	ratio := 0.0
	if pure > 0 {
		ratio = hybrid / pure
	}
	overheadPct := 0.0
	if pure > 0 && hybrid < pure {
		overheadPct = (1 - ratio) * 100
	}
	t.Logf("REF connect-ip delta: pure=%.1f hybrid=%.1f delta=%.1f ratio=%.2f overhead=%.1f%%",
		pure, hybrid, delta, ratio, overheadPct)
	want := masque.ExportConnectStreamSynthProdMinMbps
	if hybrid < want {
		t.Logf("hybrid below DoD %.0f (need connect-ip packet plane fix)", want)
	}
	if pure > 0 && hybrid < pure*masque.ExportConnectStreamSynthParityMinRatio {
		t.Logf("hybrid %.1f below pure×%.2f (%.1f)", hybrid, masque.ExportConnectStreamSynthParityMinRatio, pure*masque.ExportConnectStreamSynthParityMinRatio)
	}
}

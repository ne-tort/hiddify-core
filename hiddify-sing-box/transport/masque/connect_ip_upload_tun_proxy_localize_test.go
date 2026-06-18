package masque_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

// TestLocalizeConnectIPUploadNativeConcurrentDownloadPollution measures upload while a background
// download leg runs on the same native H3 session (localize shared QUIC conn contention; not Docker order).
func TestLocalizeConnectIPUploadNativeConcurrentDownloadPollution(t *testing.T) {
	uploadLn := startConnectIPNativeUploadSink(t)
	downLn := startHybridConnectIPDownloadTarget(t)
	proxyPort := startHybridConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	session, err := (masque.CoreClientFactory{}).NewSession(ctx, masque.ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TransportMode:       "connect_ip",
		TCPTransport:        "connect_ip",
	})
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer session.Close()
	if _, err := session.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("dial download: %v", err)
	}
	downDone := make(chan struct{})
	go func() {
		defer close(downDone)
		_, _, _ = measureNativeDownloadReadMbps(downConn, connectIPNativeSynthBenchDur)
		_ = downConn.Close()
	}()

	upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
	upConn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", upPort))
	if err != nil {
		t.Fatalf("dial upload: %v", err)
	}
	upBytes, pollutedMbps, upErr := measureNativeUploadMbps(upConn, connectIPNativeSynthBenchDur)
	_ = upConn.Close()
	<-downDone

	if upErr != nil && upBytes == 0 {
		t.Fatalf("upload: %v", upErr)
	}

	pipe := masque.ExportBenchConnectIPUploadInstantL1(t, masque.ExportLocalizeBenchDuration)
	if pipe.Err != nil {
		t.Fatalf("pipe L1: %v", pipe.Err)
	}
	ratio := pollutedMbps / pipe.Mbps
	t.Logf("concurrent download pollution: pipe=%.1f upload=%.1f ratio=%.2f", pipe.Mbps, pollutedMbps, ratio)
	t.Logf("hint: %s", masque.ExportConnectIPUploadNativeHint(pipe.Mbps, pollutedMbps))

	const pollutionCollapseRatio = 0.15
	if ratio < pollutionCollapseRatio {
		t.Logf("OPEN: concurrent download starves upload (ratio %.2f) — datagram scheduler / shared conn FC; Docker uses sequential legs", ratio)
	}
	if pollutedMbps >= masque.ExportConnectIPSynthRegressionFloorUpMbps {
		t.Logf("upload holds regression floor under concurrent download (%.1f Mbps)", pollutedMbps)
	}
}

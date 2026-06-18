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

// TestGATEConnectIPUploadSynthNative completes the upload synth gate with native H3 C2S.
// FAIL on regression floor or native/pipe ratio → QUIC/datagram bottleneck; Docker only after PASS.
func TestGATEConnectIPUploadSynthNative(t *testing.T) {
	duration := masque.ExportLocalizeBenchDuration

	pipe := masque.ExportBenchConnectIPUploadInstantL1(t, duration)
	if pipe.Err != nil {
		t.Fatalf("pipe L1: %v", pipe.Err)
	}
	t.Logf("pipe L1 upload (no QUIC): %.1f Mbit/s", pipe.Mbps)

	uploadLn := startConnectIPNativeUploadSink(t)
	proxyPort := startHybridConnectIPH3Server(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	session, err := (masque.CoreClientFactory{}).NewSession(ctx, masque.ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TransportMode:       "connect_ip",
		TCPTransport:        "connect_ip",
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer session.Close()
	if _, err := session.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}

	upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
	upConn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", upPort))
	if err != nil {
		t.Fatalf("DialContext upload: %v", err)
	}
	defer upConn.Close()

	upBytes, nativeMbps, upErr := measureNativeUploadMbps(upConn, connectIPNativeSynthBenchDur)
	if upErr != nil && upBytes == 0 {
		t.Fatalf("native upload: %v", upErr)
	}

	ratio := 0.0
	if pipe.Mbps > 0 {
		ratio = nativeMbps / pipe.Mbps
	}
	t.Logf("native H3 upload: %.1f Mbit/s; native/pipe=%.2f (min %.2f)",
		nativeMbps, ratio, masque.ExportConnectIPSynthPipeMinRatio)
	t.Logf("localization: %s", masque.ExportConnectIPUploadNativeHint(pipe.Mbps, nativeMbps))

	if nativeMbps < masque.ExportConnectIPSynthRegressionFloorUpMbps {
		t.Fatalf("native upload regression: %.1f < %.1f Mbit/s",
			nativeMbps, masque.ExportConnectIPSynthRegressionFloorUpMbps)
	}
	if ratio < masque.ExportConnectIPSynthPipeMinRatio {
		t.Fatalf("native/pipe ratio %.2f < %.2f — QUIC/datagram C2S is dominant bottleneck (Docker would not help)",
			ratio, masque.ExportConnectIPSynthPipeMinRatio)
	}
	if nativeMbps < masque.ExportConnectIPSynthProdMinMbps {
		t.Logf("OPEN: native upload %.1f < DoD %.0f — synth gate PASS; Docker connect-ip-h3-tun @0ms is next KPI",
			nativeMbps, masque.ExportConnectIPSynthProdMinMbps)
	}
}

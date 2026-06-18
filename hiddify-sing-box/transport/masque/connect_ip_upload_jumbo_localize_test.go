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

// TestLocalizeConnectIPUploadJumboCeiling probes whether larger datagram MTU lifts native upload (pps ceiling).
func TestLocalizeConnectIPUploadJumboCeiling(t *testing.T) {
	t.Setenv("HIDDIFY_MASQUE_DATAGRAM_CEILING_MAX", "4096")

	duration := masque.ExportLocalizeBenchDuration
	pipe := masque.ExportBenchConnectIPUploadInstantL1(t, duration)
	if pipe.Err != nil {
		t.Fatalf("pipe L1: %v", pipe.Err)
	}

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
		t.Fatalf("session: %v", err)
	}
	defer session.Close()
	if _, err := session.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}
	upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
	upConn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", upPort))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer upConn.Close()
	upBytes, nativeMbps, upErr := measureNativeUploadMbps(upConn, connectIPNativeSynthBenchDur)
	if upErr != nil && upBytes == 0 {
		t.Fatalf("upload: %v", upErr)
	}

	ratio := nativeMbps / pipe.Mbps
	t.Logf("jumbo ceiling 4096: pipe=%.1f native=%.1f ratio=%.2f", pipe.Mbps, nativeMbps, ratio)

	if nativeMbps < masque.ExportConnectIPSynthRegressionFloorUpMbps {
		t.Fatalf("native upload regression: %.1f < %.1f", nativeMbps, masque.ExportConnectIPSynthRegressionFloorUpMbps)
	}
	if ratio < masque.ExportConnectIPSynthPipeMinRatio {
		t.Fatalf("native/pipe %.2f < %.2f under jumbo ceiling", ratio, masque.ExportConnectIPSynthPipeMinRatio)
	}
	if nativeMbps < masque.ExportConnectIPSynthProdMinMbps {
		t.Logf("OPEN: jumbo native %.1f < DoD %.0f (jumbo helps localize pps vs ACK-clock; Docker still required)",
			nativeMbps, masque.ExportConnectIPSynthProdMinMbps)
	}
}

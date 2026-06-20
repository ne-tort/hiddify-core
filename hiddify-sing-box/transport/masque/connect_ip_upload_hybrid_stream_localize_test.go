package masque_test

import (
	"context"
	"crypto/tls"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

// TestLocalizeConnectIPUploadNativeVsHybridStreamUpload localizes datagram-per-segment overhead:
// same H3 server, same upload sink — connect_stream TCP leg vs native connect_ip packet plane.
func TestLocalizeConnectIPUploadNativeVsHybridStreamUpload(t *testing.T) {
	uploadLn := startConnectIPNativeUploadSink(t)
	proxyPort := startHybridConnectIPH3Server(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
	dest := M.ParseSocksaddrHostPort("127.0.0.1", upPort)

	measure := func(tcpTransport string) float64 {
		t.Helper()
		sess, err := (masque.CoreClientFactory{}).NewSession(ctx, masque.ClientOptions{
			Server:              "127.0.0.1",
			ServerPort:          uint16(proxyPort),
			MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
			TransportMode:       "connect_ip",
			TCPTransport:        tcpTransport,
		})
		if err != nil {
			t.Fatalf("%s session: %v", tcpTransport, err)
		}
		defer sess.Close()
		if _, err := sess.OpenIPSession(ctx); err != nil {
			t.Fatalf("%s OpenIPSession: %v", tcpTransport, err)
		}
		conn, err := sess.DialContext(ctx, "tcp", dest)
		if err != nil {
			t.Fatalf("%s dial: %v", tcpTransport, err)
		}
		defer conn.Close()
		_, mbps, err := measureNativeUploadMbps(conn, connectIPNativeSynthBenchDur)
		if err != nil {
			t.Logf("%s upload ended: %v", tcpTransport, err)
		}
		return mbps
	}

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	streamMbps := measure("connect_stream")
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	nativeMbps := measure("connect_ip")

	ratio := 0.0
	if streamMbps > 0 {
		ratio = nativeMbps / streamMbps
	}
	t.Logf("upload localize stream=%.1f native=%.1f native/stream=%.2f", streamMbps, nativeMbps, ratio)

	if nativeMbps < masque.ExportConnectIPSynthRegressionFloorUpMbps {
		t.Fatalf("native upload regression: %.1f < %.1f", nativeMbps, masque.ExportConnectIPSynthRegressionFloorUpMbps)
	}
	if streamMbps < masque.ExportConnectIPSynthRegressionFloorUpMbps {
		t.Fatalf("connect_stream upload regression: %.1f < %.1f", streamMbps, masque.ExportConnectIPSynthRegressionFloorUpMbps)
	}
	const datagramOverheadMaxRatio = 0.75
	if ratio < datagramOverheadMaxRatio {
		t.Logf("OPEN: native/stream %.2f < %.2f — datagram-per-segment is dominant vs connect_stream TCP leg",
			ratio, datagramOverheadMaxRatio)
	}
}

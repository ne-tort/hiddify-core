package masque_test

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

// TestLocalizeConnectIPUploadDatagramWakeCoalescing guards coalesced QUIC send wake on upload.
// Native connect_ip defers egress flush to ingress read-batch; wake/est_dgram should stay near 1.
func TestLocalizeConnectIPUploadDatagramWakeCoalescing(t *testing.T) {
	var wakeCount atomic.Int64
	restore := quic.SetMasqueWakeConnSendHook(func() { wakeCount.Add(1) })
	defer restore()

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

	wakeCount.Store(0)
	upBytes, nativeMbps, upErr := measureNativeUploadMbps(upConn, 1500*time.Millisecond)
	if upErr != nil && upBytes == 0 {
		t.Fatalf("upload: %v", upErr)
	}
	wakes := wakeCount.Load()
	estDatagrams := upBytes / int64(masque.ExportConnectIPSynthWakeEstSegmentBytes)
	if estDatagrams < 1 {
		estDatagrams = 1
	}
	wakePerDatagram := float64(wakes) / float64(estDatagrams)
	t.Logf("wake coalesce obs: native=%.1f Mbit/s bytes=%d wakes=%d est_dgrams=%d (seg~%dB) wake/est_dgram=%.3f",
		nativeMbps, upBytes, wakes, estDatagrams, masque.ExportConnectIPSynthWakeEstSegmentBytes, wakePerDatagram)

	if nativeMbps < masque.ExportConnectIPSynthRegressionFloorUpMbps {
		t.Fatalf("native upload regression: %.1f < %.1f Mbit/s", nativeMbps, masque.ExportConnectIPSynthRegressionFloorUpMbps)
	}
	if wakePerDatagram > 1.5 {
		t.Fatalf("wake storm: wake/est_dgram=%.3f > 1.5 — egress/ingress wake not coalesced",
			wakePerDatagram)
	}
}

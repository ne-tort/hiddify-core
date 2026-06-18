package masque_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

// TestLocalizeConnectIPUploadNativeObs logs drop counters and native/pipe ratio (localization only).
func TestLocalizeConnectIPUploadNativeObs(t *testing.T) {
	duration := masque.ExportLocalizeBenchDuration
	pipe := masque.ExportBenchConnectIPUploadInstantL1(t, duration)
	if pipe.Err != nil {
		t.Fatalf("pipe L1: %v", pipe.Err)
	}

	streamDropBefore := http3.StreamDatagramQueueDropTotal()
	rcvDropBefore := quic.DatagramReceiveQueueDropTotal()

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

	streamDrop := http3.StreamDatagramQueueDropTotal() - streamDropBefore
	rcvDrop := quic.DatagramReceiveQueueDropTotal() - rcvDropBefore
	ratio := nativeMbps / pipe.Mbps

	t.Logf("localize upload obs: pipe=%.1f native=%.1f ratio=%.2f stream_drops=%d rcv_drops=%d",
		pipe.Mbps, nativeMbps, ratio, streamDrop, rcvDrop)
	t.Logf("hint: %s", masque.ExportConnectIPUploadNativeHint(pipe.Mbps, nativeMbps))

	if streamDrop > 0 || rcvDrop > 0 {
		t.Fatalf("datagram drops during upload: stream=%d rcv=%d — fix ingress/queue before Docker",
			streamDrop, rcvDrop)
	}
}

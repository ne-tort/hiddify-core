package masque

import (
	"context"
	"crypto/tls"
	"io"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

// TestGATEH3ConnectStreamThinSocksSmoke verifies thin_bidi dataplane through in-process SOCKS router.
func TestGATEH3ConnectStreamThinSocksSmoke(t *testing.T) {
	targetPort := startH2FakeIperfStreamingDownloadTarget(t)
	proxyPort := startInProcessTCPConnectStreamRelayProxy(t)
	waitCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(proxyPort),
		ConnectStreamMode:        "thin_bidi",
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH3,
		MasqueQUICCryptoTLS:      &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer session.Close()
	socksPort := startH3ConnectStreamSocksRouterWithSession(t, session)
	conn := socksTCPDial(t, socksPort, targetPort)
	defer conn.Close()
	banner := make([]byte, 8)
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if string(banner) != "iperf3\r\n" {
		t.Fatalf("banner=%q", string(banner))
	}
}

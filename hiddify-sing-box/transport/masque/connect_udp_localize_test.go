package masque

// Localize L1 for CONNECT-UDP: in-process HTTP/3 proxy + UDP echo, no artificial link window.

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

const connectUDPLocalizeFastMbps = 80.0

func benchConnectUDPInstantRoundtrip(t *testing.T, duration time.Duration) (int64, float64, error) {
	t.Helper()
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})

	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = session.Close() }()

	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = pkt.Close() }()

	payload := make([]byte, 1200)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	buf := make([]byte, 2048)
	deadline := time.Now().Add(duration)
	var total int64
	for time.Now().Before(deadline) {
		_ = pkt.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := pkt.WriteTo(payload, echoAddr); err != nil {
			if total > 0 {
				break
			}
			return 0, 0, err
		}
		_ = pkt.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := pkt.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && total > 0 {
				break
			}
			if total > 0 {
				break
			}
			return 0, 0, err
		}
		total += int64(n) * 2
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return total, float64(total*8) / secs / 1e6, nil
}

// TestConnectUDPLocalizeInstantRoundtrip benches CONNECT-UDP echo on an instant in-process link (localize L1).
func TestConnectUDPLocalizeInstantRoundtrip(t *testing.T) {
	const duration = 400 * time.Millisecond
	bytes, mbps, err := benchConnectUDPInstantRoundtrip(t, duration)
	if err != nil {
		t.Fatalf("connect-udp localize L1 roundtrip: %v", err)
	}
	t.Logf("connect-udp localize L1 roundtrip: %.1f Mbit/s (%d bytes)", mbps, bytes)
	if mbps < connectUDPLocalizeFastMbps {
		t.Fatalf("L1 roundtrip slow: %.1f Mbit/s (want >= %.0f)", mbps, connectUDPLocalizeFastMbps)
	}
}

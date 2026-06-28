package masque

// Inttest exports for connectudp/inttest (external test package). Not a stable public API.

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func InttestRunUDPEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	return echo.LocalAddr().(*net.UDPAddr)
}

func InttestStartMasqueUDPProxyWithRelay(t *testing.T) int {
	t.Helper()
	return startInProcessMasqueUDPProxyWithRelay(t)
}

func InttestStartMasqueUDPProxyForbidden(t *testing.T) int {
	t.Helper()
	return startInProcessMasqueUDPProxyForbidden(t)
}

func InttestNewConnectUDPH3Session(t *testing.T, proxyPort int) (ClientSession, context.Context) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	t.Cleanup(cancel)
	session, err := NewConnectUDPTestSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("new connect-udp h3 session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, waitCtx
}

func InttestListenPacketConnectUDP(t *testing.T, session ClientSession, ctx context.Context, echo *net.UDPAddr) net.PacketConn {
	t.Helper()
	pkt, err := session.ListenPacket(ctx, M.Socksaddr{
		Addr: netip.MustParseAddr(echo.IP.String()),
		Port: uint16(echo.Port),
	})
	if err != nil {
		t.Fatalf("listenpacket connect-udp: %v", err)
	}
	t.Cleanup(func() { _ = pkt.Close() })
	return pkt
}

func InttestStartH2UDPConnectProxy(t *testing.T) int {
	t.Helper()
	return startInProcessH2UDPConnectProxy(t)
}

func InttestNewH2ConnectUDPSession(t *testing.T, proxyPort int) (ClientSession, context.Context) {
	t.Helper()
	return newH2ConnectUDPSession(t, proxyPort, instantH2Link{})
}

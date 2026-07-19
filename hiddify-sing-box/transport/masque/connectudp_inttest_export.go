package masque

// Inttest exports for connectudp/inttest (external test package). Not a stable public API.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	qmasque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
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

func InttestStartMasqueUDPProxyWithRelayRFCInterop(t *testing.T) int {
	t.Helper()
	return startInProcessMasqueUDPProxyWithRelayPolicy(t, cudprelay.RelayPayloadRFCInterop)
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
		PathUDP:             connectUDPInProcessPathUDP,
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

func InttestNewMasqueGoUDPClient(t *testing.T) (*qmasque.Client, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	client := &qmasque.Client{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
		},
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, ctx
}

func InttestMasqueGoUDPProxyTemplate(t *testing.T, proxyPort int) *uritemplate.Template {
	t.Helper()
	raw := fmt.Sprintf("https://127.0.0.1:%d/masque/udp/{target_host}/{target_port}", proxyPort)
	tmpl, err := uritemplate.New(raw)
	if err != nil {
		t.Fatalf("udp template: %v", err)
	}
	return tmpl
}

func InttestMasqueGoDialUDP(t *testing.T, client *qmasque.Client, ctx context.Context, tmpl *uritemplate.Template, echo *net.UDPAddr) (net.PacketConn, *http.Response) {
	t.Helper()
	target := fmt.Sprintf("%s:%d", echo.IP.String(), echo.Port)
	pkt, resp, err := client.DialAddr(ctx, tmpl, target)
	if err != nil {
		t.Fatalf("masque-go DialAddr: %v", err)
	}
	t.Cleanup(func() { _ = pkt.Close() })
	return pkt, resp
}

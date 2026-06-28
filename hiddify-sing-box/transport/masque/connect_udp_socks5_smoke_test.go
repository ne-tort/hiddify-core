package masque

// In-process SOCKS5 UDP ASSOCIATE → masque transport_mode=connect_udp → local UDP echo.
// Uses sing/protocol/socks.HandleConnectionEx + adapter.NewRouteHandlerEx — the same relay
// path as sing-box socks/mixed inbound without full box JSON or Docker.

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/route"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

func socksUDPAssociateEcho(t *testing.T, clientPort uint16, echoAddr *net.UDPAddr) {
	t.Helper()
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", clientPort), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	pc, err := dialer.ListenPacket(ctx, M.ParseSocksaddrHostPort(echoAddr.IP.String(), uint16(echoAddr.Port)))
	if err != nil {
		t.Fatalf("socks udp associate: %v", err)
	}
	defer pc.Close()

	payload := []byte("masque-connect-udp-socks5-smoke")
	if err := pc.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if err := pc.SetWriteDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	if _, err := pc.WriteTo(payload, echoAddr); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2048)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf[:n], payload)
	}
	if addr.String() != echoAddr.String() {
		t.Fatalf("unexpected source addr %v want %v", addr, echoAddr)
	}
}

func runConnectUDPSocks5Smoke(t *testing.T, inboundType string) {
	t.Helper()
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})
	session := startConnectUDPMasqueSession(t, proxyPort)

	out := &masqueSessionOutbound{
		Adapter: outbound.NewAdapter(C.TypeMasque, "masque-out", []string{N.NetworkTCP, N.NetworkUDP}, nil),
		sess:    session,
	}
	cm := route.NewConnectionManager(log.StdLogger())
	t.Cleanup(func() { _ = cm.Close() })
	router := &directMasqueRouter{cm: cm, dialer: out}

	clientPort := startSocks5AssociateRelay(t, router, inboundType)
	socksUDPAssociateEcho(t, clientPort, echoAddr)
}

// TestConnectUDPSocks5AssociateEchoInProcess routes SOCKS5 UDP ASSOCIATE (socks inbound path)
// to CONNECT-UDP masque session (transport_mode=connect_udp).
func TestConnectUDPSocks5AssociateEchoInProcess(t *testing.T) {
	runConnectUDPSocks5Smoke(t, C.TypeSOCKS)
}

// TestConnectUDPMixedInboundSocks5UDPEchoInProcess uses the same HandleConnectionEx relay with
// mixed inbound metadata — SOCKS5 UDP leg parity for mixed inbound routing.
func TestConnectUDPMixedInboundSocks5UDPEchoInProcess(t *testing.T) {
	runConnectUDPSocks5Smoke(t, C.TypeMixed)
}

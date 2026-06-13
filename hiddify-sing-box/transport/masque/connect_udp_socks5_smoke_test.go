package masque

// In-process SOCKS5 UDP ASSOCIATE → masque transport_mode=connect_udp → local UDP echo.
// Uses sing/protocol/socks.HandleConnectionEx + adapter.NewRouteHandlerEx — the same relay
// path as sing-box socks/mixed inbound without full box JSON or Docker.

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

type directMasqueRouter struct {
	cm     *route.ConnectionManager
	dialer adapter.Outbound
}

func (r *directMasqueRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	done := make(chan struct{})
	r.RouteConnectionEx(ctx, conn, metadata, N.OnceClose(func(error) { close(done) }))
	<-done
	return nil
}

func (r *directMasqueRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.cm.NewConnection(ctx, r.dialer, conn, metadata, onClose)
}

func (r *directMasqueRouter) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	done := make(chan struct{})
	r.RoutePacketConnectionEx(ctx, conn, metadata, N.OnceClose(func(error) { close(done) }))
	<-done
	return nil
}

func (r *directMasqueRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.cm.NewPacketConnection(ctx, r.dialer, conn, metadata, onClose)
}

type masqueSessionOutbound struct {
	outbound.Adapter
	sess ClientSession
}

func (o *masqueSessionOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return o.sess.DialContext(ctx, network, destination)
}

func (o *masqueSessionOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return o.sess.ListenPacket(ctx, destination)
}

func startConnectUDPMasqueSession(t *testing.T, proxyPort int) ClientSession {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		TransportMode:       option.MasqueTransportModeConnectUDP,
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("new connect_udp session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func startSocks5AssociateRelay(t *testing.T, router adapter.ConnectionRouterEx, inboundType string) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks tcp: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	upstream := adapter.NewRouteHandlerEx(adapter.InboundContext{
		Inbound:     "socks-in",
		InboundType: inboundType,
	}, router)

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				_ = socks.HandleConnectionEx(
					context.Background(),
					c,
					bufio.NewReader(c),
					nil,
					upstream,
					nil,
					C.UDPTimeout,
					M.SocksaddrFromNet(c.RemoteAddr()),
					nil,
				)
			}(conn)
		}
	}()
	time.Sleep(20 * time.Millisecond)
	return port
}

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

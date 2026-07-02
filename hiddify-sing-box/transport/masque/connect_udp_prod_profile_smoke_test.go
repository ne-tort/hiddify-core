package masque

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	connectUDPProdProfileH3SmokePayload = "connect-udp-h3-smoke"
	connectUDPProdProfileH2SmokePayload = "connect-udp-h2-smoke"
)

func connectUDPProdProfileEcho(t *testing.T, pkt net.PacketConn, echoAddr *net.UDPAddr, payload []byte) {
	t.Helper()
	if err := pkt.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if err := pkt.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	if _, err := pkt.WriteTo(payload, echoAddr); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2048)
	n, addr, err := pkt.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n == 0 {
		t.Fatal("expected non-zero echo bytes")
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", buf[:n], payload)
	}
	if udpBack, ok := addr.(*net.UDPAddr); ok {
		if !udpBack.IP.Equal(echoAddr.IP) || udpBack.Port != echoAddr.Port {
			t.Fatalf("unexpected source addr %v want %v", addr, echoAddr)
		}
	} else if addr.String() != echoAddr.String() {
		t.Fatalf("unexpected source addr %v want %v", addr, echoAddr)
	}
}

func newConnectUDPProdProfileH3Session(t *testing.T, proxyPort int) (ClientSession, context.Context) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("new connect-udp-h3 session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, waitCtx
}

func newConnectUDPProdProfileH2Session(t *testing.T, proxyPort int) (ClientSession, context.Context) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(proxyPort),
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
		MasqueQUICCryptoTLS:      &tls.Config{InsecureSkipVerify: true},
		TCPDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := baseDial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
	})
	if err != nil {
		t.Fatalf("new connect-udp-h2 session: %v", err)
	}
	t.Cleanup(func() { closeConnectUDPTestSession(session) })
	return session, waitCtx
}

// TestConnectUDPProdProfileH3CapsuleSmoke exercises prod connect-udp-h3 profile in-proc:
// transport_mode=connect_udp, H3 QUIC datagram path, ListenPacket UDP echo.
// in-proc prod-profile capsule smoke (connect-udp-h3 docker profile gate anchor).
func TestConnectUDPProdProfileH3CapsuleSmoke(t *testing.T) {
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})

	session, waitCtx := newConnectUDPProdProfileH3Session(t, proxyPort)
	if !session.Capabilities().ConnectUDP {
		t.Fatal("expected ConnectUDP capability on connect-udp-h3 session")
	}

	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket connect-udp-h3: %v", err)
	}
	defer func() { _ = pkt.Close() }()

	connectUDPProdProfileEcho(t, pkt, echoAddr, []byte(connectUDPProdProfileH3SmokePayload))
}

// TestConnectUDPProdProfileH2CapsuleSmoke exercises prod connect-udp-h2 profile in-proc:
// transport_mode=connect_udp, H2 Extended CONNECT capsule path (DatagramSplitConn), UDP echo.
func TestConnectUDPProdProfileH2CapsuleSmoke(t *testing.T) {
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newConnectUDPProdProfileH2Session(t, proxyPort)
	if !session.Capabilities().ConnectUDP {
		t.Fatal("expected ConnectUDP capability on connect-udp-h2 session")
	}

	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket connect-udp-h2: %v", err)
	}
	defer func() { _ = pkt.Close() }()

	connectUDPProdProfileEcho(t, pkt, echoAddr, []byte(connectUDPProdProfileH2SmokePayload))
}

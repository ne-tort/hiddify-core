package masque

// H2 CONNECT-UDP client harness: production ListenPacket → DatagramSplitConn (parity with connect_udp_harness_test.go H3).

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	cudp "github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

type h2TransportLink interface {
	wrapTCP(net.Conn) net.Conn
}

type instantH2Link struct{}

func (instantH2Link) wrapTCP(c net.Conn) net.Conn { return c }

func newH2ConnectUDPSession(t *testing.T, proxyPort int, link h2TransportLink) (ClientSession, context.Context) {
	t.Helper()
	if link == nil {
		link = instantH2Link{}
	}
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
			return link.wrapTCP(conn), nil
		},
	})
	if err != nil {
		t.Fatalf("new h2 connect-udp session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, waitCtx
}

// TestCoreSessionConnectUDPEchoH2ListenPacketInProcess exercises ListenPacket CONNECT-UDP over H2
// (DatagramSplitConn wrapper) against an in-process Extended CONNECT proxy.
func TestCoreSessionConnectUDPEchoH2ListenPacketInProcess(t *testing.T) {
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newH2ConnectUDPSession(t, proxyPort, instantH2Link{})

	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("listenpacket connect-udp h2: %v", err)
	}
	defer func() { _ = pkt.Close() }()
	if _, ok := pkt.(*cudp.DatagramSplitConn); !ok {
		t.Fatalf("expected DatagramSplitConn wrapper, got %T", pkt)
	}

	payload := []byte("masque-udp-h2-harness-echo-ping")
	dest := echoAddr
	if err := pkt.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if err := pkt.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	if _, err := pkt.WriteTo(payload, dest); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2048)
	n, addr, err := pkt.ReadFrom(buf)
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

// TestCoreSessionConnectUDPSplitPayloadEchoH2ListenPacketInProcess verifies DatagramSplitConn splits
// large WriteTo across H2 DATAGRAM capsules and reassembles echo replies.
func TestCoreSessionConnectUDPSplitPayloadEchoH2ListenPacketInProcess(t *testing.T) {
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newH2ConnectUDPSession(t, proxyPort, instantH2Link{})

	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("listenpacket connect-udp h2: %v", err)
	}
	defer func() { _ = pkt.Close() }()

	wantLen := 2500
	payload := make([]byte, wantLen)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	dest := echoAddr
	deadline := time.Now().Add(4 * time.Second)
	if err := pkt.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if err := pkt.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	nWr, err := pkt.WriteTo(payload, dest)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if nWr != wantLen {
		t.Fatalf("short write: %d want %d", nWr, wantLen)
	}

	got := make([]byte, 0, wantLen)
	buf := make([]byte, 2048)
	for len(got) < wantLen {
		n, addr, err := pkt.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read: %v (got %d bytes)", err, len(got))
		}
		if addr.String() != echoAddr.String() {
			t.Fatalf("unexpected source addr %v want %v", addr, echoAddr)
		}
		got = append(got, buf[:n]...)
	}
	if string(got) != string(payload) {
		t.Fatalf("split echo mismatch (len got=%d want=%d)", len(got), wantLen)
	}
}

// TestCoreSessionConnectUDPH2PortUnreachableListenPacket surfaces ICMP port-unreachable through the
// production ListenPacket → DatagramSplitConn path (TUN read-before-write parity with H3).
func TestCoreSessionConnectUDPH2PortUnreachableListenPacket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("connected UDP ICMP port-unreachable is unreliable on Windows")
	}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	t.Cleanup(func() { _ = tcpLn.Close() })
	tcpPort := tcpLn.Addr().(*net.TCPAddr).Port

	proxyPort := startInProcessH2UDPConnectProxy(t)
	session, waitCtx := newH2ConnectUDPSession(t, proxyPort, instantH2Link{})

	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr("127.0.0.1"),
		Port: uint16(tcpPort),
	})
	if err != nil {
		t.Fatalf("listenpacket connect-udp h2: %v", err)
	}
	defer func() { _ = pkt.Close() }()

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 512)
		n, _, rerr := pkt.ReadFrom(buf)
		if rerr != nil {
			errCh <- rerr
			return
		}
		if n != 0 {
			errCh <- context.Canceled
			return
		}
		errCh <- nil
	}()
	time.Sleep(30 * time.Millisecond)
	if _, werr := pkt.WriteTo([]byte{0x00, 0x01, 0x02}, nil); werr != nil {
		t.Fatalf("write: %v", werr)
	}
	select {
	case rerr := <-errCh:
		if !cudp.IsPortUnreachable(rerr) {
			t.Fatalf("expected port unreachable, got %v", rerr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFrom blocked past upload (TUN order deadlock)")
	}
}

package masque

// H2 CONNECT-UDP client harness: production ListenPacket → DatagramSplitConn (parity with connectudp_harness_test.go H3).

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	cudph2 "github.com/sagernet/sing-box/transport/masque/connectudp/h2"
	cudpsplit "github.com/sagernet/sing-box/transport/masque/connectudp/split"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
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
	t.Cleanup(func() { closeConnectUDPTestSession(session) })
	return session, waitCtx
}

func newH2OverlayDirectDialConfig(tb testing.TB, proxyPort int, link h2TransportLink) cudph2.H2OverlayDialConfig {
	tb.Helper()
	if link == nil {
		link = instantH2Link{}
	}
	clientTLS := connectUDPTestTLS.Clone()
	clientTLS.InsecureSkipVerify = true
	clientTLS.ServerName = "127.0.0.1"
	tr, err := h2c.NewClientTransport(h2c.ClientDialConfig{
		TLSConfig:          clientTLS,
		DialHostCandidates: []string{""},
		TCPDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			conn, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return link.wrapTCP(conn), nil
		},
	})
	if err != nil {
		tb.Fatalf("h2 overlay transport: %v", err)
	}
	return cudph2.H2OverlayDialConfig{
		EnsureTransport: func(context.Context) (*http2.Transport, error) {
			return tr, nil
		},
		ResolveDialAddr: func() string {
			return net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort))
		},
	}
}

func dialH2OverlayDirect(tb testing.TB, proxyPort int, link h2TransportLink, target string) net.PacketConn {
	tb.Helper()
	rawTpl := "https://127.0.0.1:" + strconv.Itoa(proxyPort) + "/masque/udp/{target_host}/{target_port}"
	tpl, err := uritemplate.New(rawTpl)
	if err != nil {
		tb.Fatalf("template: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	tb.Cleanup(cancel)
	pc, err := cudph2.DialH2Overlay(ctx, newH2OverlayDirectDialConfig(tb, proxyPort, link), tpl, target)
	if err != nil {
		tb.Fatalf("DialH2Overlay: %v", err)
	}
	tb.Cleanup(func() { _ = pc.Close() })
	return pc
}

func benchConnectUDPH2OverlayDirectUpload(
	tb testing.TB,
	link h2TransportLink,
	duration time.Duration,
	payloadLen int,
) (int64, float64, error) {
	tb.Helper()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	sink, _ := runUDPSink(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(tb)
	pkt := dialH2OverlayDirect(tb, proxyPort, link, net.JoinHostPort(sinkAddr.IP.String(), strconv.Itoa(sinkAddr.Port)))
	return benchConnectUDPPacketUpload(tb, pkt, sinkAddr, duration, 0, payloadLen)
}

func benchConnectUDPH2OverlayDirectDownloadFountain(
	tb testing.TB,
	link h2TransportLink,
	duration time.Duration,
	payloadLen int,
) (int64, float64, error) {
	tb.Helper()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	fountain := startUDPFountain(tb, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	fountainAddr := fountain.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(tb)
	pkt := dialH2OverlayDirect(tb, proxyPort, link, net.JoinHostPort(fountainAddr.IP.String(), strconv.Itoa(fountainAddr.Port)))
	if err := primeUDPBenchErr(tb, pkt, fountainAddr); err != nil {
		return 0, 0, err
	}
	return benchConnectUDPPacketReceiveOnly(tb, pkt, duration, payloadLen)
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
		if !cudpsplit.IsPortUnreachable(rerr) {
			t.Fatalf("expected port unreachable, got %v", rerr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFrom blocked past upload (TUN order deadlock)")
	}
}

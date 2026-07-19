package inttest_test

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	masque "github.com/sagernet/sing-box/transport/masque"
	cudpsplit "github.com/sagernet/sing-box/transport/masque/connectudp/split"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	M "github.com/sagernet/sing/common/metadata"
)

func TestCoreSessionConnectUDPEchoH2ListenPacketInProcess(t *testing.T) {
	echoAddr := masque.InttestRunUDPEcho(t)
	proxyPort := masque.InttestStartH2UDPConnectProxy(t)
	session, waitCtx := masque.InttestNewH2ConnectUDPSession(t, proxyPort)
	pkt := listenPacketH2(t, session, waitCtx, echoAddr)

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

func TestCoreSessionConnectUDPSplitPayloadEchoH2ListenPacketInProcess(t *testing.T) {
	echoAddr := masque.InttestRunUDPEcho(t)
	proxyPort := masque.InttestStartH2UDPConnectProxy(t)
	session, waitCtx := masque.InttestNewH2ConnectUDPSession(t, proxyPort)
	pkt := listenPacketH2(t, session, waitCtx, echoAddr)

	wantLen := h2c.MaxUDPPayloadPerDatagramCapsule()
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
		t.Fatalf("max-capsule echo mismatch (len got=%d want=%d)", len(got), wantLen)
	}
}

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

	proxyPort := masque.InttestStartH2UDPConnectProxy(t)
	session, waitCtx := masque.InttestNewH2ConnectUDPSession(t, proxyPort)
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

func listenPacketH2(t *testing.T, session masque.ClientSession, ctx context.Context, echo *net.UDPAddr) net.PacketConn {
	t.Helper()
	pkt, err := session.ListenPacket(ctx, M.Socksaddr{
		Addr: netip.MustParseAddr(echo.IP.String()),
		Port: uint16(echo.Port),
	})
	if err != nil {
		t.Fatalf("listenpacket connect-udp h2: %v", err)
	}
	t.Cleanup(func() { _ = pkt.Close() })
	return pkt
}

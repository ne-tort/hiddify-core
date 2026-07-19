package inttest_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	masque "github.com/sagernet/sing-box/transport/masque"
	cudpconn "github.com/sagernet/sing-box/transport/masque/connectudp/conn"
	cudpsplit "github.com/sagernet/sing-box/transport/masque/connectudp/split"
	M "github.com/sagernet/sing/common/metadata"
)

func TestCoreSessionConnectUDPEchoInProcess(t *testing.T) {
	echoAddr := masque.InttestRunUDPEcho(t)
	proxyPort := masque.InttestStartMasqueUDPProxyWithRelay(t)
	session, waitCtx := masque.InttestNewConnectUDPH3Session(t, proxyPort)
	pkt := masque.InttestListenPacketConnectUDP(t, session, waitCtx, echoAddr)

	payload := []byte("masque-udp-harness-echo-ping")
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
	if !inttestUDPTargetAddrEqual(addr, echoAddr) {
		t.Fatalf("unexpected source addr %v want %v", addr, echoAddr)
	}
}

func inttestUDPTargetAddrEqual(addr net.Addr, want *net.UDPAddr) bool {
	if addr == nil || want == nil {
		return false
	}
	if ua, ok := addr.(*net.UDPAddr); ok {
		return ua.IP.Equal(want.IP) && ua.Port == want.Port
	}
	ah, ap, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	wh, wp, err := net.SplitHostPort(want.String())
	if err != nil {
		return false
	}
	return net.ParseIP(ah).Equal(net.ParseIP(wh)) && ap == wp
}

func TestCoreSessionConnectUDPSplitPayloadEchoInProcess(t *testing.T) {
	skipH3MultiDatagramWindows(t)
	echoAddr := masque.InttestRunUDPEcho(t)
	proxyPort := masque.InttestStartMasqueUDPProxyWithRelay(t)
	session, waitCtx := masque.InttestNewConnectUDPH3Session(t, proxyPort)
	pkt := masque.InttestListenPacketConnectUDP(t, session, waitCtx, echoAddr)

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
		if !inttestUDPTargetAddrEqual(addr, echoAddr) {
			t.Fatalf("unexpected source addr %v want %v", addr, echoAddr)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, payload) {
		for i := range got {
			if got[i] != payload[i] {
				t.Fatalf("split echo mismatch at %d: got=%d want=%d", i, got[i], payload[i])
			}
		}
		t.Fatalf("split echo mismatch (len got=%d want=%d)", len(got), wantLen)
	}
}

func TestCoreSessionConnectUDPForbiddenBeforeProxy(t *testing.T) {
	proxyPort := masque.InttestStartMasqueUDPProxyForbidden(t)
	session, waitCtx := masque.InttestNewConnectUDPH3Session(t, proxyPort)
	_, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr("127.0.0.1"),
		Port: 9,
	})
	if err == nil {
		t.Fatal("expected ListenPacket to fail when proxy responds 403")
	}
}

func TestCoreSessionConnectUDPH3PortUnreachableListenPacket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("connected UDP ICMP port-unreachable is unreliable on Windows")
	}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	t.Cleanup(func() { _ = tcpLn.Close() })
	tcpPort := tcpLn.Addr().(*net.TCPAddr).Port

	proxyPort := masque.InttestStartMasqueUDPProxyWithRelay(t)
	session, waitCtx := masque.InttestNewConnectUDPH3Session(t, proxyPort)
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr("127.0.0.1"),
		Port: uint16(tcpPort),
	})
	if err != nil {
		t.Fatalf("listenpacket connect-udp h3: %v", err)
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
		if !errors.Is(rerr, cudpconn.ErrICMPPortUnreachable) && !cudpsplit.IsPortUnreachable(rerr) {
			t.Fatalf("expected port unreachable, got %v", rerr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFrom blocked past upload (ICMP soft-signal timeout)")
	}
}

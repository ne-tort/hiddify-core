package inttest_test

import (
	"bytes"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	masque "github.com/sagernet/sing-box/transport/masque"
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
	udpBack, ok := addr.(*net.UDPAddr)
	if !ok || !udpBack.IP.Equal(echoAddr.IP) || udpBack.Port != echoAddr.Port {
		t.Fatalf("unexpected source addr %v want %v", addr, echoAddr)
	}
}

func TestCoreSessionConnectUDPSplitPayloadEchoInProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("H3 multi-datagram echo reassembly order unreliable on Windows loopback")
	}
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
		udpBack, ok := addr.(*net.UDPAddr)
		if !ok || !udpBack.IP.Equal(echoAddr.IP) || udpBack.Port != echoAddr.Port {
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

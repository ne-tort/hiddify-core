package inttest_test

import (
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

// TestLocalizeConnectUDPH3PortUnreachableDockerShape is the docker-KPI harness naming for
// soft ICMP (empty ctx0 → port unreachable). In-proc Linux only; not a PTB test.
func TestLocalizeConnectUDPH3PortUnreachableDockerShape(t *testing.T) {
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
		t.Fatalf("listenpacket: %v", err)
	}
	t.Cleanup(func() { _ = pkt.Close() })

	deadline := time.Now().Add(3 * time.Second)
	if err := pkt.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if err := pkt.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}

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
	time.Sleep(20 * time.Millisecond)
	if _, werr := pkt.WriteTo([]byte{0xde, 0xad}, nil); werr != nil {
		t.Fatalf("write: %v", werr)
	}
	select {
	case rerr := <-errCh:
		if !errors.Is(rerr, cudpconn.ErrICMPPortUnreachable) && !cudpsplit.IsPortUnreachable(rerr) {
			t.Fatalf("docker-shape soft ICMP: got %v", rerr)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("docker-shape soft ICMP: ReadFrom timeout")
	}
}

package forwarder

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

type recordingConnectIPConn struct {
	mu      sync.Mutex
	written [][]byte
}

func (r *recordingConnectIPConn) ReadPacket([]byte) (int, error) {
	<-time.After(24 * time.Hour)
	return 0, nil
}

func (r *recordingConnectIPConn) WritePacket(p []byte) ([]byte, error) {
	r.mu.Lock()
	r.written = append(r.written, append([]byte(nil), p...))
	r.mu.Unlock()
	return nil, nil
}

func (r *recordingConnectIPConn) Close() error { return nil }

func (r *recordingConnectIPConn) CurrentPeerPrefixes() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")}
}

func TestUDPForwarderSendICMPPortUnreachable(t *testing.T) {
	t.Parallel()
	orig, err := buildIPv4UDPPacket(
		netip.MustParseAddr("198.18.0.2"), 53000,
		netip.MustParseAddr("10.0.0.1"), 5201,
		[]byte("x"),
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	rec := &recordingConnectIPConn{}
	f := &packetForwarder{conn: rec}
	if err := f.sendICMPPortUnreachable(orig); err != nil {
		t.Fatalf("send icmp: %v", err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.written) != 1 {
		t.Fatalf("written=%d want 1", len(rec.written))
	}
	if _, _, ok := cip.ParseICMPPortUnreachablePeer(rec.written[0]); !ok {
		t.Fatalf("not icmp port unreachable pkt_len=%d", len(rec.written[0]))
	}
}

func TestUDPForwarderICMPPortUnreachableOnClosedPort(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("connected UDP ICMP port-unreachable is unreliable on Windows")
	}
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := uint16(ln.LocalAddr().(*net.UDPAddr).Port)
	_ = ln.Close()

	rec := &recordingConnectIPConn{}
	f := &packetForwarder{
		conn: rec,
		o: ConnectIPTCPForwarderOptions{
			AllowPrivateTargets: true,
			Dialer:              net.Dialer{Timeout: 2 * time.Second},
		},
	}
	src := tcpip.AddrFrom4([4]byte{198, 18, 0, 2})
	dst := tcpip.AddrFrom4([4]byte{127, 0, 0, 1})
	payload := []byte("dig-probe")
	pkt, err := buildIPv4UDPPacket(netip.AddrFrom4(src.As4()), 53000, netip.AddrFrom4(dst.As4()), port, payload)
	if err != nil {
		t.Fatalf("build udp: %v", err)
	}
	iph := header.IPv4(pkt)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	f.handleUDPPacket(ctx, pkt, iph)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rec.mu.Lock()
		n := len(rec.written)
		rec.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	var icmpReply []byte
	for _, w := range rec.written {
		if len(w) >= 28 && w[9] == 1 && w[20] == 3 && w[21] == 3 {
			icmpReply = w
			break
		}
	}
	if icmpReply == nil {
		t.Fatalf("no ICMP port-unreachable written; got %d packets", len(rec.written))
	}
	peer, p, ok := cip.ParseICMPPortUnreachablePeer(icmpReply)
	if !ok || peer != netip.AddrFrom4(dst.As4()) || p != port {
		t.Fatalf("parse icmp: peer=%v port=%d ok=%v", peer, p, ok)
	}
}

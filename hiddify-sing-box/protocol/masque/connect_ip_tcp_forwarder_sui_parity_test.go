package masque

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque/server"
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
	M "github.com/sagernet/sing/common/metadata"
)

// TestConnectIPTCPForwarderSuiParityConstants locks CLIENT-SERVER-CONTRACTS invariants so the
// sing-box server path used by s-ui cannot drift from transport/masque/forwarder (single impl).
func TestConnectIPTCPForwarderSuiParityConstants(t *testing.T) {
	t.Parallel()
	if server.ConnectIPMaxICMPRelay != 8 {
		t.Fatalf("ConnectIPMaxICMPRelay=%d want 8", server.ConnectIPMaxICMPRelay)
	}
	if fwd.WriteQueueDepth != 512 {
		t.Fatalf("forwarder WriteQueueDepth=%d want 512", fwd.WriteQueueDepth)
	}
	ceiling := cip.DatagramCeilingMax()
	maxIPv4 := cip.MaxIPv4Datagram(ceiling)
	if maxIPv4 != fwd.DefaultDatagramCeilingMax-fwd.DatagramSlack {
		t.Fatalf("client MaxIPv4Datagram=%d forwarder max=%d", maxIPv4, fwd.DefaultDatagramCeilingMax-fwd.DatagramSlack)
	}
}

// TestConnectIPTCPForwarderSuiParityPipeE2E exercises server.RouteConnectIPBlocked →
// fwd.RunConnectIPTCPPacketPlaneForwarder
// over a packet pipe (no quic-go / docker). s-ui runs the same sing-box ServerEndpoint stack.
func TestConnectIPTCPForwarderSuiParityPipeE2E(t *testing.T) {
	t.Parallel()
	runConnectIPTCPForwarderSuiParityPipe(t, false)
}

// TestConnectIPTCPForwarderSuiParityPipeBulk verifies the server forwarder path sustains bulk
// upload (not a client-only optimization); same shared forwarder as transport localize tests.
func TestConnectIPTCPForwarderSuiParityPipeBulk(t *testing.T) {
	t.Parallel()
	runConnectIPTCPForwarderSuiParityPipe(t, true)
}

func runConnectIPTCPForwarderSuiParityPipe(t *testing.T, bulk bool) {
	t.Helper()

	clientSess, serverSess := newMasquePacketPipePair()
	peer := netip.MustParsePrefix("198.18.0.2/32")

	remoteLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("remote listen: %v", err)
	}
	t.Cleanup(func() { _ = remoteLn.Close() })
	remotePort := uint16(remoteLn.Addr().(*net.TCPAddr).Port)

	go func() {
		for {
			c, err := remoteLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if bulk {
					buf := make([]byte, 256*1024)
					deadline := time.Now().Add(400 * time.Millisecond)
					for time.Now().Before(deadline) {
						_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
						if _, err := c.Read(buf); err != nil {
							return
						}
					}
					return
				}
				buf := make([]byte, 64)
				n, err := c.Read(buf)
				if err != nil || n == 0 {
					return
				}
				_, _ = c.Write(buf[:n])
			}(c)
		}
	}()

	clientNS, err := cip.NewNetstack(context.Background(), clientSess, cip.NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		MTU:       1372,
	})
	if err != nil {
		t.Fatalf("client netstack: %v", err)
	}
	waitIngress := runMasquePipeIngressRelay(clientSess, clientNS)

	packetConn := server.NewConnectIPNetPacketConn(&pipePacketPlaneConn{
		session:      serverSess,
		peerPrefixes: []netip.Prefix{peer},
	})

	routeCtx, routeCancel := context.WithCancel(context.Background())
	routeDone := make(chan struct{})
	go func() {
		defer close(routeDone)
		server.RouteConnectIPBlocked(nil, routeCtx, packetConn, adapter.InboundContext{}, nil, option.MasqueEndpointOptions{
			AllowPrivateTargets: true,
		}, net.Dialer{})
	}()

	t.Cleanup(func() {
		routeCancel()
		_ = clientNS.Close()
		_ = clientSess.Close()
		_ = serverSess.Close()
		waitIngress()
		select {
		case <-routeDone:
		case <-time.After(3 * time.Second):
			t.Log("server.RouteConnectIPBlocked did not exit promptly after cleanup")
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := clientNS.DialContext(ctx, M.ParseSocksaddrHostPort("127.0.0.1", remotePort))
	if err != nil {
		t.Fatalf("dial tcp over connect-ip sui-parity pipe: %v", err)
	}
	defer conn.Close()

	if bulk {
		buf := make([]byte, 256*1024)
		deadline := time.Now().Add(400 * time.Millisecond)
		var total int64
		for time.Now().Before(deadline) {
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			n, err := conn.Write(buf)
			if n > 0 {
				total += int64(n)
			}
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() && total > 0 {
					break
				}
				if total > 0 {
					break
				}
				t.Fatalf("bulk write: %v", err)
			}
		}
		const wantMin = 256 * 1024
		if total < wantMin {
			t.Fatalf("bulk upload=%d bytes want >= %d through server.RouteConnectIPBlocked", total, wantMin)
		}
		return
	}

	msg := []byte("sui-parity-connect-ip-pipe")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(reply, msg) {
		t.Fatalf("echo mismatch: got %q want %q", reply, msg)
	}
}

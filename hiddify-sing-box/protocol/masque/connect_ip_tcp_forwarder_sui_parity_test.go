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
	if server.ConnectIPMaxParseDropPerRead != 64 {
		t.Fatalf("ConnectIPMaxParseDropPerRead=%d want 64", server.ConnectIPMaxParseDropPerRead)
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

// TestConnectIPTCPForwarderRestartAcceptance models docker bench upload → server Close+Start → download:
// phase-1 route stops after egress flush; phase-2 fresh pipe route must download.
// Not parallel: lifecycle timing is load-sensitive under L5 gate.
func TestConnectIPTCPForwarderRestartAcceptance(t *testing.T) {

	_, remotePort := startConnectIPPipeRemoteBulkServer(t)
	peer := netip.MustParsePrefix("198.18.0.2/32")
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	clientSess1, rawServer1 := newMasquePacketPipePair()
	serverSess1 := &benignOncePipeSession{inner: rawServer1}
	clientNS1, route1 := startConnectIPPipeRoute(t, clientSess1, serverSess1, peer)

	upConn, err := clientNS1.DialContext(ctx, M.ParseSocksaddrHostPort("127.0.0.1", remotePort))
	if err != nil {
		t.Fatalf("dial upload: %v", err)
	}
	buf := make([]byte, 256*1024)
	uploadDeadline := time.Now().Add(300 * time.Millisecond)
	var upBytes int64
	for time.Now().Before(uploadDeadline) {
		_ = upConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		n, err := upConn.Write(buf)
		if n > 0 {
			upBytes += int64(n)
		}
		if err != nil {
			break
		}
	}
	serverSess1.ArmTeardown0x100()
	if err := upConn.Close(); err != nil {
		t.Fatalf("close upload: %v", err)
	}
	flushPipeEgress(clientNS1)
	stopConnectIPPipeRoute(t, route1, clientNS1, clientSess1, serverSess1)

	clientSess2, serverSess2 := newMasquePacketPipePair()
	clientNS2, route2 := startConnectIPPipeRoute(t, clientSess2, serverSess2, peer)
	defer stopConnectIPPipeRoute(t, route2, clientNS2, clientSess2, serverSess2)

	downConn, err := clientNS2.DialContext(ctx, M.ParseSocksaddrHostPort("127.0.0.1", remotePort))
	if err != nil {
		t.Fatalf("dial download after restart: %v", err)
	}
	defer downConn.Close()

	downDeadline := time.Now().Add(400 * time.Millisecond)
	var downBytes int64
	for time.Now().Before(downDeadline) {
		_ = downConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := downConn.Read(buf)
		if n > 0 {
			downBytes += int64(n)
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && downBytes > 0 {
				break
			}
			if downBytes > 0 {
				break
			}
			t.Fatalf("download after restart read: %v", err)
		}
	}
	t.Logf("restart-acceptance upload=%d download=%d bytes", upBytes, downBytes)
	if downBytes < 32*1024 {
		t.Fatalf("download after restart=%d bytes want >= 32KiB", downBytes)
	}
}

// TestConnectIPTCPForwarderSuiParityRecycle verifies bulk upload teardown (incl. benign 0x100)
// on the same RouteConnectIPBlocked handler allows a fresh download without docker restart.
func TestConnectIPTCPForwarderSuiParityRecycle(t *testing.T) {
	// Not parallel: 0x100 teardown + recycle timing is load-sensitive under L5 gate.

	clientSess, rawServerSess := newMasquePacketPipePair()
	serverSess := &benignOncePipeSession{inner: rawServerSess}
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
				peek := make([]byte, 1)
				_ = c.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
				n, _ := c.Read(peek)
				if n == 0 {
					payload := make([]byte, 64*1024)
					deadline := time.Now().Add(400 * time.Millisecond)
					for time.Now().Before(deadline) {
						if _, err := c.Write(payload); err != nil {
							return
						}
					}
					return
				}
				buf := make([]byte, 256*1024)
				deadline := time.Now().Add(400 * time.Millisecond)
				for time.Now().Before(deadline) {
					_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
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

	upConn, err := clientNS.DialContext(ctx, M.ParseSocksaddrHostPort("127.0.0.1", remotePort))
	if err != nil {
		t.Fatalf("dial upload: %v", err)
	}
	buf := make([]byte, 256*1024)
	uploadDeadline := time.Now().Add(300 * time.Millisecond)
	var upBytes int64
	for time.Now().Before(uploadDeadline) {
		_ = upConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		n, err := upConn.Write(buf)
		if n > 0 {
			upBytes += int64(n)
		}
		if err != nil {
			break
		}
	}
	serverSess.ArmTeardown0x100()
	if err := upConn.Close(); err != nil {
		t.Fatalf("close upload: %v", err)
	}
	flushPipeEgress(clientNS)

	downConn, err := clientNS.DialContext(ctx, M.ParseSocksaddrHostPort("127.0.0.1", remotePort))
	if err != nil {
		t.Fatalf("dial download after recycle: %v", err)
	}
	defer downConn.Close()

	downDeadline := time.Now().Add(400 * time.Millisecond)
	var downBytes int64
	for time.Now().Before(downDeadline) {
		_ = downConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := downConn.Read(buf)
		if n > 0 {
			downBytes += int64(n)
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && downBytes > 0 {
				break
			}
			if downBytes > 0 {
				break
			}
			t.Fatalf("download read: %v", err)
		}
	}
	t.Logf("sui-parity recycle upload=%d download=%d bytes", upBytes, downBytes)
	if downBytes < 32*1024 {
		t.Fatalf("download after recycle=%d bytes want >= 32KiB on same RouteConnectIPBlocked", downBytes)
	}
}

// TestConnectIPRestartReadinessSynDialAfterUpload verifies a fresh TCP dial (SYN) completes
// quickly after upload teardown on the same RouteConnectIPBlocked — parity with run_local.py
// double TCP probe after server restart (nc -z is insufficient when forwarder is not ready).
// Not parallel: latency guard is CPU-sensitive under full L5 gate load.
func TestConnectIPRestartReadinessSynDialAfterUpload(t *testing.T) {

	clientSess, rawServerSess := newMasquePacketPipePair()
	serverSess := &benignOncePipeSession{inner: rawServerSess}
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
				peek := make([]byte, 1)
				_ = c.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
				n, _ := c.Read(peek)
				if n > 0 {
					buf := make([]byte, 256*1024)
					deadline := time.Now().Add(400 * time.Millisecond)
					for time.Now().Before(deadline) {
						_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
						if _, err := c.Read(buf); err != nil {
							return
						}
					}
				}
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

	upConn, err := clientNS.DialContext(ctx, M.ParseSocksaddrHostPort("127.0.0.1", remotePort))
	if err != nil {
		t.Fatalf("dial upload warmup: %v", err)
	}
	if _, err := upConn.Write([]byte("warmup")); err != nil {
		t.Fatalf("upload warmup: %v", err)
	}
	if err := upConn.Close(); err != nil {
		t.Fatalf("close upload: %v", err)
	}
	flushPipeEgress(clientNS)

	start := time.Now()
	recycleConn, err := clientNS.DialContext(ctx, M.ParseSocksaddrHostPort("127.0.0.1", remotePort))
	latency := time.Since(start)
	if err != nil {
		t.Fatalf("SYN dial after upload recycle: %v", err)
	}
	if err := recycleConn.Close(); err != nil {
		t.Fatalf("close recycle dial: %v", err)
	}
	const maxSynReady = 750 * time.Millisecond
	t.Logf("RouteConnectIPBlocked SYN-ready after upload recycle: %v", latency)
	if latency > maxSynReady {
		t.Fatalf("SYN dial after upload recycle took %v want < %v", latency, maxSynReady)
	}
}

func flushPipeEgress(ns *cip.Netstack) {
	if ns == nil {
		return
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ns.ScheduleOutboundDrain()
		if ns.OutboundQueueDepth() == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
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

type connectIPPipeRoute struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func startConnectIPPipeRemoteBulkServer(t *testing.T) (net.Listener, uint16) {
	t.Helper()
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
				peek := make([]byte, 1)
				_ = c.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
				n, _ := c.Read(peek)
				if n == 0 {
					payload := make([]byte, 64*1024)
					deadline := time.Now().Add(400 * time.Millisecond)
					for time.Now().Before(deadline) {
						if _, err := c.Write(payload); err != nil {
							return
						}
					}
					return
				}
				buf := make([]byte, 256*1024)
				deadline := time.Now().Add(400 * time.Millisecond)
				for time.Now().Before(deadline) {
					_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return remoteLn, remotePort
}

func startConnectIPPipeRoute(t *testing.T, clientSess *masquePacketPipeSession, serverSess pipePacketSession, peer netip.Prefix) (*cip.Netstack, *connectIPPipeRoute) {
	t.Helper()
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
	return clientNS, &connectIPPipeRoute{
		cancel: func() {
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
		},
		done: routeDone,
	}
}

func stopConnectIPPipeRoute(t *testing.T, route *connectIPPipeRoute, _ *cip.Netstack, _, _ pipePacketSession) {
	t.Helper()
	if route == nil {
		return
	}
	route.cancel()
}

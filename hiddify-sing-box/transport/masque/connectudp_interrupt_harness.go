package masque

// Interrupt/close harness for GATE leak + selector tests (inttest export).

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

type interruptCloseMode int

const (
	interruptCloseUpload interruptCloseMode = iota
	interruptCloseRead
)

func runConnectUDPInterruptCloseGate(t *testing.T, leg string, open func(*testing.T) net.PacketConn) {
	t.Helper()
	runConnectUDPInterruptCloseGateWithMode(t, leg, interruptCloseUpload, open)
}

func runConnectUDPInterruptCloseGateWithMode(t *testing.T, leg string, mode interruptCloseMode, open func(*testing.T) net.PacketConn) {
	t.Helper()
	pkt := open(t)
	t.Cleanup(func() { _ = pkt.Close() })

	grp := interrupt.NewGroup()
	wrapped := grp.NewPacketConn(pkt, true)

	payload := make([]byte, connectudp.DefaultBenchUDPPayloadLen)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}

	var ioWG sync.WaitGroup
	ioWG.Add(1)
	go func() {
		defer ioWG.Done()
		switch mode {
		case interruptCloseRead:
			buf := make([]byte, connectudp.DefaultBenchUDPPayloadLen)
			for i := 0; i < 8; i++ {
				_ = wrapped.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, _, err := wrapped.ReadFrom(buf); err != nil {
					return
				}
			}
		default:
			for i := 0; i < 256; i++ {
				if _, err := wrapped.WriteTo(payload, addr); err != nil {
					return
				}
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)

	interruptDone := make(chan struct{})
	go func() {
		grp.Interrupt(true)
		close(interruptDone)
	}()

	select {
	case <-interruptDone:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: interrupt.Group.Interrupt hung >2s (selector switch contract)", leg)
	}

	ioDone := make(chan struct{})
	go func() {
		ioWG.Wait()
		close(ioDone)
	}()
	select {
	case <-ioDone:
	case <-time.After(2 * time.Second):
		op := "WriteTo"
		if mode == interruptCloseRead {
			op = "ReadFrom"
		}
		t.Fatalf("%s: %s goroutine hung after interrupt", leg, op)
	}
}

func openConnectUDPH3PacketOnProxy(t *testing.T, proxyPort int) (net.PacketConn, func()) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	session, err := NewConnectUDPTestSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		cancel()
		t.Fatalf("session: %v", err)
	}
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr("127.0.0.1"),
		Port: 9,
	})
	if err != nil {
		closeConnectUDPTestSession(session)
		cancel()
		t.Fatalf("ListenPacket: %v", err)
	}
	cleanup := func() {
		_ = pkt.Close()
		closeConnectUDPTestSession(session)
		cancel()
	}
	return pkt, cleanup
}

func openConnectUDPH2PacketOnProxy(t *testing.T, proxyPort int) (net.PacketConn, func()) {
	t.Helper()
	session, waitCtx := newH2ConnectUDPSession(t, proxyPort, instantH2Link{})
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr("127.0.0.1"),
		Port: 9,
	})
	if err != nil {
		closeConnectUDPTestSession(session)
		t.Fatalf("ListenPacket: %v", err)
	}
	return pkt, func() {
		_ = pkt.Close()
		closeConnectUDPTestSession(session)
	}
}

func runConnectUDPInterruptCycle(
	t *testing.T,
	leg string,
	mode interruptCloseMode,
	open func(*testing.T) (net.PacketConn, func()),
) {
	t.Helper()
	pkt, cleanup := open(t)
	defer cleanup()

	grp := interrupt.NewGroup()
	wrapped := grp.NewPacketConn(pkt, true)

	payload := make([]byte, connectudp.DefaultBenchUDPPayloadLen)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}

	var ioWG sync.WaitGroup
	ioWG.Add(1)
	go func() {
		defer ioWG.Done()
		switch mode {
		case interruptCloseRead:
			buf := make([]byte, connectudp.DefaultBenchUDPPayloadLen)
			for j := 0; j < 8; j++ {
				_ = wrapped.SetReadDeadline(time.Now().Add(2 * time.Second))
				if _, _, err := wrapped.ReadFrom(buf); err != nil {
					return
				}
			}
		default:
			for j := 0; j < 64; j++ {
				if _, err := wrapped.WriteTo(payload, addr); err != nil {
					return
				}
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)
	grp.Interrupt(true)

	done := make(chan struct{})
	go func() {
		ioWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: I/O goroutine hung after interrupt", leg)
	}
}

func runConnectUDPSessionCloseCycleH3(t *testing.T, proxyPort int) {
	t.Helper()
	pkt, cleanup := openConnectUDPH3PacketOnProxy(t, proxyPort)
	defer cleanup()

	payload := make([]byte, connectudp.DefaultBenchUDPPayloadLen)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	for j := 0; j < 32; j++ {
		if _, err := pkt.WriteTo(payload, addr); err != nil {
			break
		}
	}
}

func runConnectUDPSessionCloseCycleH2(t *testing.T, proxyPort int) {
	t.Helper()
	pkt, cleanup := openConnectUDPH2PacketOnProxy(t, proxyPort)
	defer cleanup()

	payload := make([]byte, connectudp.DefaultBenchUDPPayloadLen)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	for j := 0; j < 32; j++ {
		if _, err := pkt.WriteTo(payload, addr); err != nil {
			break
		}
	}
}

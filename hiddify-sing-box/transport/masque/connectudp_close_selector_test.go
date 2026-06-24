package masque

// GATE-CONNECT-UDP-CLOSE: selector interrupt / outbound switch must close tunnels without hang.

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

func TestGATEConnectUDPH3InterruptClosesWithoutHang(t *testing.T) {
	runConnectUDPInterruptCloseGate(t, "h3", func(t *testing.T) net.PacketConn {
		t.Helper()
		pkt, _ := newConnectUDPH3ProdListenPacket(t, M.Socksaddr{
			Addr: netip.MustParseAddr("127.0.0.1"),
			Port: 9,
		})
		return pkt
	})
}

func TestGATEConnectUDPH2InterruptClosesWithoutHang(t *testing.T) {
	runConnectUDPInterruptCloseGate(t, "h2", func(t *testing.T) net.PacketConn {
		t.Helper()
		proxyPort := startInProcessH2UDPConnectProxy(t)
		session, waitCtx := newH2ConnectUDPSession(t, proxyPort, instantH2Link{})
		pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
			Addr: netip.MustParseAddr("127.0.0.1"),
			Port: 9,
		})
		if err != nil {
			t.Fatalf("ListenPacket: %v", err)
		}
		return pkt
	})
}

func TestGATEConnectUDPH3InterruptClosesBlockedReadWithoutHang(t *testing.T) {
	runConnectUDPInterruptCloseGateWithMode(t, "h3-read", interruptCloseRead, func(t *testing.T) net.PacketConn {
		t.Helper()
		pkt, _ := newConnectUDPH3ProdListenPacket(t, M.Socksaddr{
			Addr: netip.MustParseAddr("127.0.0.1"),
			Port: 9,
		})
		return pkt
	})
}

func TestGATEConnectUDPH2InterruptClosesBlockedReadWithoutHang(t *testing.T) {
	runConnectUDPInterruptCloseGateWithMode(t, "h2-read", interruptCloseRead, func(t *testing.T) net.PacketConn {
		t.Helper()
		proxyPort := startInProcessH2UDPConnectProxy(t)
		session, waitCtx := newH2ConnectUDPSession(t, proxyPort, instantH2Link{})
		pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
			Addr: netip.MustParseAddr("127.0.0.1"),
			Port: 9,
		})
		if err != nil {
			t.Fatalf("ListenPacket: %v", err)
		}
		return pkt
	})
}

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

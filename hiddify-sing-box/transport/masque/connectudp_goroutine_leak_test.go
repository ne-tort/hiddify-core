package masque

// GATE-CONNECT-UDP-CLOSE: no goroutine leaks after selector interrupt or session teardown.

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

func TestGATEConnectUDPH3InterruptNoGoroutineLeak(t *testing.T) {
	trackConnectUDPGoroutines(t)
	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})
	for range 4 {
		runConnectUDPInterruptCycle(t, "h3", interruptCloseUpload, func(t *testing.T) (net.PacketConn, func()) {
			return openConnectUDPH3PacketOnProxy(t, proxyPort)
		})
	}
}

func TestGATEConnectUDPH2InterruptNoGoroutineLeak(t *testing.T) {
	trackConnectUDPGoroutines(t)
	proxyPort := startInProcessH2UDPConnectProxy(t)
	for range 4 {
		runConnectUDPInterruptCycle(t, "h2", interruptCloseUpload, func(t *testing.T) (net.PacketConn, func()) {
			return openConnectUDPH2PacketOnProxy(t, proxyPort)
		})
	}
}

func TestGATEConnectUDPH3InterruptBlockedReadNoGoroutineLeak(t *testing.T) {
	trackConnectUDPGoroutines(t)
	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})
	for range 3 {
		runConnectUDPInterruptCycle(t, "h3-read", interruptCloseRead, func(t *testing.T) (net.PacketConn, func()) {
			return openConnectUDPH3PacketOnProxy(t, proxyPort)
		})
	}
}

func TestGATEConnectUDPH2InterruptBlockedReadNoGoroutineLeak(t *testing.T) {
	trackConnectUDPGoroutines(t)
	proxyPort := startInProcessH2UDPConnectProxy(t)
	for range 3 {
		runConnectUDPInterruptCycle(t, "h2-read", interruptCloseRead, func(t *testing.T) (net.PacketConn, func()) {
			return openConnectUDPH2PacketOnProxy(t, proxyPort)
		})
	}
}

func TestGATEConnectUDPH3SessionCloseNoGoroutineLeak(t *testing.T) {
	trackConnectUDPGoroutines(t)
	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})
	for range 3 {
		runConnectUDPSessionCloseCycleH3(t, proxyPort)
	}
}

func TestGATEConnectUDPH2SessionCloseNoGoroutineLeak(t *testing.T) {
	trackConnectUDPGoroutines(t)
	proxyPort := startInProcessH2UDPConnectProxy(t)
	for range 3 {
		runConnectUDPSessionCloseCycleH2(t, proxyPort)
	}
}

func openConnectUDPH3PacketOnProxy(t *testing.T, proxyPort int) (net.PacketConn, func()) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	session, err := NewConnectUDPTestSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		TransportMode:       option.MasqueTransportModeConnectUDP,
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

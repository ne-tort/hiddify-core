package masque

import (
	"net"
	"net/http"
	"net/netip"
	"testing"
	M "github.com/sagernet/sing/common/metadata"
)

func InttestGATEConnectUDPH3InterruptClosesWithoutHang(t *testing.T) {
	runConnectUDPInterruptCloseGate(t, "h3", func(t *testing.T) net.PacketConn {
		t.Helper()
		pkt, _ := newConnectUDPH3ProdListenPacket(t, M.Socksaddr{
			Addr: netip.MustParseAddr("127.0.0.1"),
			Port: 9,
		})
		return pkt
	})
}

func InttestGATEConnectUDPH2InterruptClosesWithoutHang(t *testing.T) {
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

func InttestGATEConnectUDPH3InterruptClosesBlockedReadWithoutHang(t *testing.T) {
	runConnectUDPInterruptCloseGateWithMode(t, "h3-read", interruptCloseRead, func(t *testing.T) net.PacketConn {
		t.Helper()
		pkt, _ := newConnectUDPH3ProdListenPacket(t, M.Socksaddr{
			Addr: netip.MustParseAddr("127.0.0.1"),
			Port: 9,
		})
		return pkt
	})
}

func InttestGATEConnectUDPH2InterruptClosesBlockedReadWithoutHang(t *testing.T) {
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

func InttestGATEConnectUDPH3InterruptNoGoroutineLeak(t *testing.T) {
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

func InttestGATEConnectUDPH2InterruptNoGoroutineLeak(t *testing.T) {
	trackConnectUDPGoroutines(t)
	proxyPort := startInProcessH2UDPConnectProxy(t)
	for range 4 {
		runConnectUDPInterruptCycle(t, "h2", interruptCloseUpload, func(t *testing.T) (net.PacketConn, func()) {
			return openConnectUDPH2PacketOnProxy(t, proxyPort)
		})
	}
}

func InttestGATEConnectUDPH3InterruptBlockedReadNoGoroutineLeak(t *testing.T) {
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

func InttestGATEConnectUDPH2InterruptBlockedReadNoGoroutineLeak(t *testing.T) {
	trackConnectUDPGoroutines(t)
	proxyPort := startInProcessH2UDPConnectProxy(t)
	for range 3 {
		runConnectUDPInterruptCycle(t, "h2-read", interruptCloseRead, func(t *testing.T) (net.PacketConn, func()) {
			return openConnectUDPH2PacketOnProxy(t, proxyPort)
		})
	}
}

func InttestGATEConnectUDPH3SessionCloseNoGoroutineLeak(t *testing.T) {
	trackConnectUDPGoroutines(t)
	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})
	for range 3 {
		runConnectUDPSessionCloseCycleH3(t, proxyPort)
	}
}

func InttestGATEConnectUDPH2SessionCloseNoGoroutineLeak(t *testing.T) {
	trackConnectUDPGoroutines(t)
	proxyPort := startInProcessH2UDPConnectProxy(t)
	for range 3 {
		runConnectUDPSessionCloseCycleH2(t, proxyPort)
	}
}

package masque

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

const (
	connectUDPCloseStormCyclesH2 = 24
	connectUDPCloseStormCyclesH3 = 8 // dedicated QUIC handshake per flow (AUDIT B11)
	connectUDPCloseStormRounds   = 2
	connectUDPCloseStormRunID    = uint32(0xF5200001)
)

// gateConnectUDPCloseStorm rapidly opens/closes CONNECT-UDP PacketConns on one CoreSession
// (H2 = asym 2-stream pairs). Asserts no hang and no goroutine leak (TASKS F5.2 / B9).
func gateConnectUDPCloseStorm(t *testing.T, layer string) {
	t.Helper()
	trackConnectUDPGoroutines(t)

	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	var proxyPort int
	switch layer {
	case "h2":
		proxyPort = startInProcessH2UDPConnectProxy(t)
	case "h3":
		proxyPort = startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, p int) {
			registerMasqueUDPProxyHandler(t, mux, p)
		})
	default:
		t.Fatalf("unknown layer %q", layer)
	}

	waitCtx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)

	var session ClientSession
	cycles := connectUDPCloseStormCyclesH2
	switch layer {
	case "h2":
		session, waitCtx = newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
	case "h3":
		cycles = connectUDPCloseStormCyclesH3
		var err error
		session, err = (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
			Server:              "127.0.0.1",
			ServerPort:          uint16(proxyPort),
			PathUDP:             connectUDPInProcessPathUDP,
			MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		})
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		t.Cleanup(func() { _ = session.Close() })
	}

	cs, ok := session.(*coreSession)
	if !ok || cs == nil {
		t.Fatal("expected *coreSession")
	}

	dest := M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	}
	for i := 0; i < cycles; i++ {
		pkt, err := session.ListenPacket(waitCtx, dest)
		if err != nil {
			t.Fatalf("ListenPacket cycle=%d: %v", i, err)
		}
		if err := runConnectUDPMultiClientProbeEcho(t, pkt, echoAddr, connectUDPCloseStormRunID+uint32(i), connectUDPCloseStormRounds); err != nil {
			_ = pkt.Close()
			t.Fatalf("probe cycle=%d: %v", i, err)
		}
		closeDone := make(chan error, 1)
		go func() { closeDone <- pkt.Close() }()
		select {
		case err := <-closeDone:
			if err != nil {
				t.Fatalf("Close cycle=%d: %v", i, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("Close hung >3s cycle=%d (asym pair / B9)", i)
		}
		if got := cs.liveUDPPacketConnCount(); got != 0 {
			t.Fatalf("live flows after close cycle=%d: %d want 0", i, got)
		}
	}

	t.Logf("GATE close-storm %s: %d open/probe/close cycles OK", layer, cycles)
}

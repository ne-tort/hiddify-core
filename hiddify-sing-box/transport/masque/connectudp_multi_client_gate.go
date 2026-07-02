package masque

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	connectUDPMultiClientProbeRounds = 32
	connectUDPMultiClientRunA        = uint32(0xC1E0A001)
	connectUDPMultiClientRunB        = uint32(0xC1E0B002)
)

// gateConnectUDPMultiClientIsolation runs two independent CoreSessions against one shared server
// and verifies sequenced probe echo isolation (zero cross-talk between run_id spaces).
func gateConnectUDPMultiClientIsolation(t *testing.T, layer string) {
	t.Helper()
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

	openSession := func() (ClientSession, context.Context) {
		t.Helper()
		waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		var session ClientSession
		var err error
		switch layer {
		case "h2":
			session, waitCtx = newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
		case "h3":
			session, err = (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
				Server:              "127.0.0.1",
				ServerPort:          uint16(proxyPort),
				MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
			})
			if err != nil {
				t.Fatalf("session: %v", err)
			}
			t.Cleanup(func() { _ = session.Close() })
		}
		return session, waitCtx
	}

	sessionA, ctxA := openSession()
	sessionB, ctxB := openSession()
	defer func() { _ = sessionA.Close() }()
	defer func() { _ = sessionB.Close() }()

	pktA, err := sessionA.ListenPacket(ctxA, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket A: %v", err)
	}
	defer func() { _ = pktA.Close() }()

	pktB, err := sessionB.ListenPacket(ctxB, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket B: %v", err)
	}
	defer func() { _ = pktB.Close() }()

	var wg sync.WaitGroup
	var errA, errB error
	wg.Add(2)
	go func() {
		defer wg.Done()
		errA = runConnectUDPMultiClientProbeEcho(t, pktA, echoAddr, connectUDPMultiClientRunA, connectUDPMultiClientProbeRounds)
	}()
	go func() {
		defer wg.Done()
		errB = runConnectUDPMultiClientProbeEcho(t, pktB, echoAddr, connectUDPMultiClientRunB, connectUDPMultiClientProbeRounds)
	}()
	wg.Wait()
	if errA != nil {
		t.Fatalf("client A isolation: %v", errA)
	}
	if errB != nil {
		t.Fatalf("client B isolation: %v", errB)
	}
	t.Logf("GATE multi-client %s: %d probes x2 clients isolated (run_id A=0x%x B=0x%x)",
		layer, connectUDPMultiClientProbeRounds, connectUDPMultiClientRunA, connectUDPMultiClientRunB)
}

func runConnectUDPMultiClientProbeEcho(tb testing.TB, pkt net.PacketConn, echoAddr net.Addr, runID uint32, rounds int) error {
	tb.Helper()
	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	buf := make([]byte, payloadLen+64)
	for seq := range uint64(rounds) {
		p := connectudp.BuildProbePayload(seq, runID, payloadLen)
		if err := writeToWithStallGuard(tb, pkt, p, echoAddr, connectUDPSynthUploadWriteStall); err != nil {
			return err
		}
		if err := readProbeWithStallGuard(tb, pkt, buf, runID, seq, connectUDPSynthUploadWriteStall); err != nil {
			return err
		}
	}
	return nil
}

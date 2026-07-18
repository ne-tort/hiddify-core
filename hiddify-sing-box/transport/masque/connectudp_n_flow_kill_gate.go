package masque

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/http2"
)

const (
	connectUDPNFlowKillCount        = 4
	connectUDPNFlowKillRoundsBefore = 8
	connectUDPNFlowKillRoundsAfter  = 16
	connectUDPNFlowKillRunBase      = uint32(0xF5100001)
)

// gateConnectUDPNFlowKillIsolation opens ≥4 CONNECT-UDP flows on one CoreSession (shared H2
// pool on h2), probes them, kills flow[0], and verifies survivors still echo with intact underlay.
// TASKS F5.1 / AUDIT multi-flow reliability.
func gateConnectUDPNFlowKillIsolation(t *testing.T, layer string) {
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

	waitCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	var session ClientSession
	switch layer {
	case "h2":
		session, waitCtx = newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
	case "h3":
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
		t.Fatal("expected *coreSession for live-flow / H2 pool asserts")
	}

	pkts := make([]net.PacketConn, connectUDPNFlowKillCount)
	runIDs := make([]uint32, connectUDPNFlowKillCount)
	for i := 0; i < connectUDPNFlowKillCount; i++ {
		runIDs[i] = connectUDPNFlowKillRunBase + uint32(i)
		pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
			Addr: netip.MustParseAddr(echoAddr.IP.String()),
			Port: uint16(echoAddr.Port),
		})
		if err != nil {
			t.Fatalf("ListenPacket %d: %v", i, err)
		}
		pkts[i] = pkt
	}
	defer func() {
		for _, p := range pkts {
			if p != nil {
				_ = p.Close()
			}
		}
	}()

	if got := cs.liveUDPPacketConnCount(); got != connectUDPNFlowKillCount {
		t.Fatalf("live flows after open=%d want %d", got, connectUDPNFlowKillCount)
	}

	var sharedH2 *http2.Transport
	if layer == "h2" {
		sharedH2 = snapshotH2UDPTransport(cs)
		if sharedH2 == nil {
			t.Fatal("expected shared H2UDPTransport after N ListenPacket")
		}
	}

	if err := runNFlowProbeParallel(t, pkts, echoAddr, runIDs, connectUDPNFlowKillRoundsBefore); err != nil {
		t.Fatalf("pre-kill probe: %v", err)
	}

	if err := pkts[0].Close(); err != nil {
		t.Fatalf("kill flow0: %v", err)
	}
	pkts[0] = nil

	if got := cs.liveUDPPacketConnCount(); got != connectUDPNFlowKillCount-1 {
		t.Fatalf("live flows after kill=%d want %d", got, connectUDPNFlowKillCount-1)
	}
	if layer == "h2" {
		if snapshotH2UDPTransport(cs) != sharedH2 {
			t.Fatal("shared H2UDPTransport must survive killing one of N flows")
		}
	}

	survivors := pkts[1:]
	survivorRuns := runIDs[1:]
	if err := runNFlowProbeParallel(t, survivors, echoAddr, survivorRuns, connectUDPNFlowKillRoundsAfter); err != nil {
		t.Fatalf("post-kill survivors: %v", err)
	}

	t.Logf("GATE n-flow-kill %s: N=%d kill=0 survivors=%d pre=%d post=%d",
		layer, connectUDPNFlowKillCount, len(survivors),
		connectUDPNFlowKillRoundsBefore, connectUDPNFlowKillRoundsAfter)
}

func snapshotH2UDPTransport(s *coreSession) *http2.Transport {
	s.H2UDPMu.Lock()
	defer s.H2UDPMu.Unlock()
	return s.H2UDPTransport
}

func runNFlowProbeParallel(t *testing.T, pkts []net.PacketConn, echoAddr net.Addr, runIDs []uint32, rounds int) error {
	t.Helper()
	if len(pkts) != len(runIDs) {
		return fmt.Errorf("pkts=%d runIDs=%d mismatch", len(pkts), len(runIDs))
	}
	var wg sync.WaitGroup
	errs := make([]error, len(pkts))
	wg.Add(len(pkts))
	for i := range pkts {
		i := i
		go func() {
			defer wg.Done()
			if pkts[i] == nil {
				errs[i] = fmt.Errorf("nil packet conn %d", i)
				return
			}
			errs[i] = runConnectUDPMultiClientProbeEcho(t, pkts[i], echoAddr, runIDs[i], rounds)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			return fmt.Errorf("flow %d: %w", i, err)
		}
	}
	return nil
}

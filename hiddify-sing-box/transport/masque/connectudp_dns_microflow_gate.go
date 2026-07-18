package masque

// DNS-like microflow gates: many short small-RTT flows (real traffic shape) and isolation
// so one flow's close/write-error must not kill siblings or the shared session underlay.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/http2"
)

const (
	connectUDPDNSMicroPayloadLen   = 48 // ~DNS query size (header 12 + pad)
	connectUDPDNSMicroFlowCount    = 16
	connectUDPDNSMicroRoundsBefore = 3
	connectUDPDNSMicroRoundsAfter  = 6
	connectUDPDNSMicroRunBase      = uint32(0xD0500001)
	connectUDPDNSChurnCycles       = 12
	connectUDPDNSChurnRounds       = 2
	connectUDPDNSStickyRounds      = 40
)

// gateConnectUDPDNSMicroflowIsolation opens many DNS-sized CONNECT-UDP flows on one CoreSession,
// probes them, kills flow[0], asserts WriteTo on the dead flow fails, and verifies survivors
// (and shared H2 transport) keep working.
func gateConnectUDPDNSMicroflowIsolation(t *testing.T, layer string) {
	t.Helper()
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	proxyPort, session, waitCtx := openDNSMicroSession(t, layer)
	_ = proxyPort
	cs, ok := session.(*coreSession)
	if !ok || cs == nil {
		t.Fatal("expected *coreSession")
	}

	n := connectUDPDNSMicroFlowCount
	pkts := make([]net.PacketConn, n)
	runIDs := make([]uint32, n)
	for i := 0; i < n; i++ {
		runIDs[i] = connectUDPDNSMicroRunBase + uint32(i)
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

	if got := cs.liveUDPPacketConnCount(); got != n {
		t.Fatalf("live flows after open=%d want %d", got, n)
	}

	var sharedH2 *http2.Transport
	if layer == "h2" {
		sharedH2 = snapshotH2UDPTransport(cs)
		if sharedH2 == nil {
			t.Fatal("expected shared H2UDPTransport after DNS micro ListenPacket")
		}
	}

	if err := runDNSMicroProbeParallel(t, pkts, echoAddr, runIDs, connectUDPDNSMicroRoundsBefore); err != nil {
		t.Fatalf("pre-kill DNS micro probe: %v", err)
	}

	victim := pkts[0]
	if err := victim.Close(); err != nil {
		t.Fatalf("kill flow0: %v", err)
	}
	pkts[0] = nil

	// Write/error on dead flow must fail locally and must not poison survivors.
	deadPayload := connectudp.BuildProbePayload(0, runIDs[0], connectUDPDNSMicroPayloadLen)
	if _, err := victim.WriteTo(deadPayload, echoAddr); err == nil {
		t.Fatal("WriteTo on closed DNS microflow must fail")
	}

	if got := cs.liveUDPPacketConnCount(); got != n-1 {
		t.Fatalf("live flows after kill=%d want %d", got, n-1)
	}
	if layer == "h2" {
		if snapshotH2UDPTransport(cs) != sharedH2 {
			t.Fatal("shared H2UDPTransport must survive killing one DNS microflow")
		}
	}

	survivors := pkts[1:]
	survivorRuns := runIDs[1:]
	if err := runDNSMicroProbeParallel(t, survivors, echoAddr, survivorRuns, connectUDPDNSMicroRoundsAfter); err != nil {
		t.Fatalf("post-kill DNS micro survivors: %v", err)
	}

	t.Logf("GATE dns-micro-isolation %s: N=%d payload=%d kill=0 survivors=%d pre=%d post=%d",
		layer, n, connectUDPDNSMicroPayloadLen, len(survivors),
		connectUDPDNSMicroRoundsBefore, connectUDPDNSMicroRoundsAfter)
}

// gateConnectUDPDNSMicroflowChurn keeps one sticky DNS-sized flow alive while rapidly
// opening/closing short-lived microflows (DNS churn). Sticky must not fail; session must
// not hang or drop the shared underlay. Goroutine-leak contract stays in close-storm (F5.2).
func gateConnectUDPDNSMicroflowChurn(t *testing.T, layer string) {
	t.Helper()

	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)
	_, session, waitCtx := openDNSMicroSession(t, layer)
	cs, ok := session.(*coreSession)
	if !ok || cs == nil {
		t.Fatal("expected *coreSession")
	}
	defer closeConnectUDPTestSession(session)

	sticky, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		t.Fatalf("sticky ListenPacket: %v", err)
	}

	var sharedH2 *http2.Transport
	if layer == "h2" {
		sharedH2 = snapshotH2UDPTransport(cs)
		if sharedH2 == nil {
			t.Fatal("expected shared H2UDPTransport for sticky DNS flow")
		}
	}

	stickyRun := connectUDPDNSMicroRunBase + 0xA000
	var stickyErr atomic.Value // error
	var stickyDone sync.WaitGroup
	stickyDone.Add(1)
	go func() {
		defer stickyDone.Done()
		if err := runConnectUDPSizedProbeEcho(t, sticky, echoAddr, stickyRun, connectUDPDNSStickyRounds, connectUDPDNSMicroPayloadLen); err != nil {
			stickyErr.Store(err)
		}
	}()

	churnBase := connectUDPDNSMicroRunBase + 0xB000
	for i := 0; i < connectUDPDNSChurnCycles; i++ {
		pkt, lerr := session.ListenPacket(waitCtx, M.Socksaddr{
			Addr: netip.MustParseAddr(echoAddr.IP.String()),
			Port: uint16(echoAddr.Port),
		})
		if lerr != nil {
			t.Fatalf("churn ListenPacket %d: %v", i, lerr)
		}
		if err := runConnectUDPSizedProbeEcho(t, pkt, echoAddr, churnBase+uint32(i), connectUDPDNSChurnRounds, connectUDPDNSMicroPayloadLen); err != nil {
			_ = pkt.Close()
			t.Fatalf("churn probe %d: %v", i, err)
		}
		if err := pkt.Close(); err != nil {
			t.Fatalf("churn close %d: %v", i, err)
		}
	}

	stickyDone.Wait()
	if v := stickyErr.Load(); v != nil {
		t.Fatalf("sticky DNS flow failed during churn: %v", v)
	}
	if layer == "h2" {
		if snapshotH2UDPTransport(cs) != sharedH2 {
			t.Fatal("shared H2UDPTransport must survive DNS microflow churn")
		}
	}
	if got := cs.liveUDPPacketConnCount(); got != 1 {
		t.Fatalf("live flows after churn=%d want 1 (sticky only)", got)
	}
	if err := sticky.Close(); err != nil {
		t.Fatalf("sticky close: %v", err)
	}
	if got := cs.liveUDPPacketConnCount(); got != 0 {
		t.Fatalf("live flows after sticky close=%d want 0", got)
	}

	t.Logf("GATE dns-micro-churn %s: sticky_rounds=%d churn_cycles=%d payload=%d",
		layer, connectUDPDNSStickyRounds, connectUDPDNSChurnCycles, connectUDPDNSMicroPayloadLen)
}

func openDNSMicroSession(t *testing.T, layer string) (proxyPort int, session ClientSession, waitCtx context.Context) {
	t.Helper()
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

	waitCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	t.Cleanup(cancel)

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
	return proxyPort, session, waitCtx
}

func runDNSMicroProbeParallel(t *testing.T, pkts []net.PacketConn, echoAddr net.Addr, runIDs []uint32, rounds int) error {
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
			errs[i] = runConnectUDPSizedProbeEcho(t, pkts[i], echoAddr, runIDs[i], rounds, connectUDPDNSMicroPayloadLen)
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

func runConnectUDPSizedProbeEcho(tb testing.TB, pkt net.PacketConn, echoAddr net.Addr, runID uint32, rounds, payloadLen int) error {
	tb.Helper()
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

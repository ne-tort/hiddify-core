package masque

// SOCKS ASSOCIATE path for DNS-like microflows (prod client shape): many short small-RTT
// associations on one CoreSession; kill/write-error and churn must not poison siblings.
//
// Note: MASQUE ListenPacket is opened lazily when the first datagram is routed through
// ConnectionManager (not at SOCKS ASSOCIATE return). Closing the SOCKS PacketConn tears
// down the masque flow asynchronously (upload drain up to ~5s in route.copyPacketUpload).

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"golang.org/x/net/http2"
)

const (
	connectUDPDNSSocksRunBase          = uint32(0xD0510001)
	connectUDPDNSSocksLiveSettleTimeout = 6 * time.Second // covers packetRelayUploadDrainTimeout=5s
)

type socksDNSMicroStack struct {
	session  ClientSession
	cs       *coreSession
	dialer   *socks.Client
	echoAddr *net.UDPAddr
	dest     M.Socksaddr
	ctx      context.Context
}

func openSocksDNSMicroStack(t *testing.T, layer string) *socksDNSMicroStack {
	t.Helper()
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	var session ClientSession
	switch layer {
	case "h3":
		proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
			registerMasqueUDPProxyHandler(t, mux, proxyPort)
		})
		session = startConnectUDPMasqueSession(t, proxyPort)
	case "h2":
		proxyPort := startInProcessH2UDPConnectProxy(t)
		session = startConnectUDPH2MasqueSession(t, proxyPort)
	default:
		t.Fatalf("unknown layer %q", layer)
	}

	cs, ok := session.(*coreSession)
	if !ok || cs == nil {
		t.Fatal("expected *coreSession behind SOCKS masque outbound")
	}

	out := &masqueSessionOutbound{
		Adapter: outbound.NewAdapter(constant.TypeMasque, "masque-out", []string{N.NetworkTCP, N.NetworkUDP}, nil),
		sess:    session,
	}
	cm := route.NewConnectionManager(log.StdLogger())
	t.Cleanup(func() { _ = cm.Close() })
	router := &directMasqueRouter{cm: cm, dialer: out}
	socksPort := startSocks5AssociateRelay(t, router, constant.TypeSOCKS)

	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", socksPort), socks.Version5, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	return &socksDNSMicroStack{
		session:  session,
		cs:       cs,
		dialer:   dialer,
		echoAddr: echoAddr,
		dest:     M.ParseSocksaddrHostPort(echoAddr.IP.String(), uint16(echoAddr.Port)),
		ctx:      ctx,
	}
}

func (s *socksDNSMicroStack) associate(t *testing.T) net.PacketConn {
	t.Helper()
	pkt, err := s.dialer.ListenPacket(s.ctx, s.dest)
	if err != nil {
		t.Fatalf("socks udp associate: %v", err)
	}
	route.TuneUDPPacketConn(pkt)
	return pkt
}

func waitLiveUDPFlows(t *testing.T, cs *coreSession, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var got int
	for time.Now().Before(deadline) {
		got = cs.liveUDPPacketConnCount()
		if got == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("live masque flows=%d want %d after %v (SOCKS↔MASQUE teardown / lazy open)", got, want, timeout)
}

// gateConnectUDPSocksDNSMicroflowIsolation opens N SOCKS UDP ASSOCIATEs (DNS-sized RTT) on one
// CoreSession, kills association[0], asserts WriteTo-on-closed fails, survivors keep echoing.
func gateConnectUDPSocksDNSMicroflowIsolation(t *testing.T, layer string) {
	t.Helper()
	stack := openSocksDNSMicroStack(t, layer)
	n := connectUDPDNSMicroFlowCount
	pkts := make([]net.PacketConn, n)
	runIDs := make([]uint32, n)
	for i := 0; i < n; i++ {
		runIDs[i] = connectUDPDNSSocksRunBase + uint32(i)
		pkts[i] = stack.associate(t)
	}
	defer func() {
		for _, p := range pkts {
			if p != nil {
				_ = p.Close()
			}
		}
	}()

	if err := runDNSMicroProbeParallel(t, pkts, stack.echoAddr, runIDs, connectUDPDNSMicroRoundsBefore); err != nil {
		t.Fatalf("pre-kill SOCKS DNS micro probe: %v", err)
	}
	// Lazy open: masque flows appear after first datagram through ConnectionManager.
	waitLiveUDPFlows(t, stack.cs, n, 2*time.Second)

	var sharedH2 *http2.Transport
	if layer == "h2" {
		sharedH2 = snapshotH2UDPTransport(stack.cs)
		if sharedH2 == nil {
			t.Fatal("expected shared H2UDPTransport after SOCKS DNS traffic")
		}
	}

	victim := pkts[0]
	if err := victim.Close(); err != nil {
		t.Fatalf("kill SOCKS associate0: %v", err)
	}
	pkts[0] = nil

	deadPayload := connectudp.BuildProbePayload(0, runIDs[0], connectUDPDNSMicroPayloadLen)
	if _, err := victim.WriteTo(deadPayload, stack.echoAddr); err == nil {
		t.Fatal("WriteTo on closed SOCKS DNS associate must fail")
	}

	waitLiveUDPFlows(t, stack.cs, n-1, connectUDPDNSSocksLiveSettleTimeout)
	if layer == "h2" {
		if snapshotH2UDPTransport(stack.cs) != sharedH2 {
			t.Fatal("shared H2UDPTransport must survive killing one SOCKS DNS associate")
		}
	}

	if err := runDNSMicroProbeParallel(t, pkts[1:], stack.echoAddr, runIDs[1:], connectUDPDNSMicroRoundsAfter); err != nil {
		t.Fatalf("post-kill SOCKS DNS survivors: %v", err)
	}

	t.Logf("GATE socks-dns-micro-isolation %s: N=%d payload=%d kill=0 survivors=%d",
		layer, n, connectUDPDNSMicroPayloadLen, n-1)
}

// gateConnectUDPSocksDNSMicroflowChurn keeps one sticky SOCKS ASSOCIATE alive while rapidly
// opening/closing short DNS-like associations (app DNS churn shape).
func gateConnectUDPSocksDNSMicroflowChurn(t *testing.T, layer string) {
	t.Helper()
	stack := openSocksDNSMicroStack(t, layer)

	sticky := stack.associate(t)
	stickyRun := connectUDPDNSSocksRunBase + 0xA000
	// Prime sticky so masque flow + H2 pool exist before churn.
	if err := runConnectUDPSizedProbeEcho(t, sticky, stack.echoAddr, stickyRun, 1, connectUDPDNSMicroPayloadLen); err != nil {
		t.Fatalf("sticky prime: %v", err)
	}
	waitLiveUDPFlows(t, stack.cs, 1, 2*time.Second)

	var sharedH2 *http2.Transport
	if layer == "h2" {
		sharedH2 = snapshotH2UDPTransport(stack.cs)
		if sharedH2 == nil {
			t.Fatal("expected shared H2UDPTransport for sticky SOCKS DNS associate")
		}
	}

	var stickyErr atomic.Value
	var stickyDone sync.WaitGroup
	stickyDone.Add(1)
	go func() {
		defer stickyDone.Done()
		// Remaining sticky rounds after prime (seq continues from 1).
		buf := make([]byte, connectUDPDNSMicroPayloadLen+64)
		for seq := uint64(1); seq < uint64(connectUDPDNSStickyRounds); seq++ {
			p := connectudp.BuildProbePayload(seq, stickyRun, connectUDPDNSMicroPayloadLen)
			if err := writeToWithStallGuard(t, sticky, p, stack.echoAddr, connectUDPSynthUploadWriteStall); err != nil {
				stickyErr.Store(err)
				return
			}
			if err := readProbeWithStallGuard(t, sticky, buf, stickyRun, seq, connectUDPSynthUploadWriteStall); err != nil {
				stickyErr.Store(err)
				return
			}
		}
	}()

	churnBase := connectUDPDNSSocksRunBase + 0xB000
	for i := 0; i < connectUDPDNSChurnCycles; i++ {
		pkt := stack.associate(t)
		if err := runConnectUDPSizedProbeEcho(t, pkt, stack.echoAddr, churnBase+uint32(i), connectUDPDNSChurnRounds, connectUDPDNSMicroPayloadLen); err != nil {
			_ = pkt.Close()
			t.Fatalf("SOCKS churn probe %d: %v", i, err)
		}
		closeDone := make(chan error, 1)
		go func() { closeDone <- pkt.Close() }()
		select {
		case err := <-closeDone:
			if err != nil {
				t.Fatalf("SOCKS churn close %d: %v", i, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("SOCKS churn Close hung >3s cycle=%d", i)
		}
	}

	stickyDone.Wait()
	if v := stickyErr.Load(); v != nil {
		t.Fatalf("sticky SOCKS DNS associate failed during churn: %v", v)
	}
	if layer == "h2" {
		if snapshotH2UDPTransport(stack.cs) != sharedH2 {
			t.Fatal("shared H2UDPTransport must survive SOCKS DNS churn")
		}
	}
	// Churn associates may still be draining upload (route packetRelayUploadDrainTimeout).
	waitLiveUDPFlows(t, stack.cs, 1, connectUDPDNSSocksLiveSettleTimeout)
	if err := sticky.Close(); err != nil {
		t.Fatalf("sticky SOCKS close: %v", err)
	}
	waitLiveUDPFlows(t, stack.cs, 0, connectUDPDNSSocksLiveSettleTimeout)

	t.Logf("GATE socks-dns-micro-churn %s: sticky_rounds=%d churn_cycles=%d payload=%d",
		layer, connectUDPDNSStickyRounds, connectUDPDNSChurnCycles, connectUDPDNSMicroPayloadLen)
}

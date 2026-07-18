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
	connectUDPTUNShapeProbeRounds = 16
	connectUDPTUNShapeRunID       = uint32(0x7B000001)
	connectUDPTUNShapePipeline    = 1

	// ASSOCIATE-like burst: N concurrent ListenPacket on one session (TUN UDP ASSOCIATE storm shape).
	connectUDPTUNShapeBurstFlows  = 4
	connectUDPTUNShapeBurstRounds = 4
	connectUDPTUNShapeBurstRunBase = uint32(0xF5300001)
)

// gateConnectUDPTUNShapeProbeEcho verifies pipeline=1 read→write echo (TUN interactive ordering)
// with sequenced probe integrity on the masque endpoint plane.
func gateConnectUDPTUNShapeProbeEcho(t *testing.T, layer string) {
	t.Helper()
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	pkt, cleanup := openConnectUDPProdListenPacket(t, layer, echoAddr)
	defer cleanup()

	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	buf := make([]byte, payloadLen+64)

	// Prime one in-flight echo (pipeline depth 1).
	prime := connectudp.BuildProbePayload(0, connectUDPTUNShapeRunID, payloadLen)
	if err := writeToWithStallGuard(t, pkt, prime, echoAddr, connectUDPSynthUploadWriteStall); err != nil {
		t.Fatalf("prime write: %v", err)
	}
	if err := readProbeWithStallGuard(t, pkt, buf, connectUDPTUNShapeRunID, 0, connectUDPSynthUploadWriteStall); err != nil {
		t.Fatalf("prime read: %v", err)
	}

	for seq := uint64(1); seq < connectUDPTUNShapeProbeRounds; seq++ {
		p := connectudp.BuildProbePayload(seq, connectUDPTUNShapeRunID, payloadLen)
		if err := writeToWithStallGuard(t, pkt, p, echoAddr, connectUDPSynthUploadWriteStall); err != nil {
			t.Fatalf("pipeline=1 write seq=%d: %v", seq, err)
		}
		if err := readProbeWithStallGuard(t, pkt, buf, connectUDPTUNShapeRunID, seq, connectUDPSynthUploadWriteStall); err != nil {
			t.Fatalf("pipeline=1 read seq=%d: %v", seq, err)
		}
	}
	t.Logf("GATE tun-shape %s pipeline=%d: %d sequenced echo RT OK",
		layer, connectUDPTUNShapePipeline, connectUDPTUNShapeProbeRounds)
}

// gateConnectUDPTUNShapeAssociateBurst opens N flows on one CoreSession in parallel (ASSOCIATE-like),
// runs short pipeline=1 probes, then closes. H3 note: each flow may use a dedicated QUIC (AUDIT B11).
func gateConnectUDPTUNShapeAssociateBurst(t *testing.T, layer string) {
	t.Helper()
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	waitCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	var proxyPort int
	var session ClientSession
	switch layer {
	case "h3":
		proxyPort = startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, p int) {
			registerMasqueUDPProxyHandler(t, mux, p)
		})
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
	case "h2":
		proxyPort = startInProcessH2UDPConnectProxy(t)
		session, waitCtx = newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
	default:
		t.Fatalf("unknown layer %q", layer)
	}

	dest := M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	}
	pkts := make([]net.PacketConn, connectUDPTUNShapeBurstFlows)
	for i := 0; i < connectUDPTUNShapeBurstFlows; i++ {
		pkt, err := session.ListenPacket(waitCtx, dest)
		if err != nil {
			t.Fatalf("ListenPacket burst %d: %v", i, err)
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

	var wg sync.WaitGroup
	errs := make([]error, len(pkts))
	wg.Add(len(pkts))
	for i := range pkts {
		i := i
		go func() {
			defer wg.Done()
			errs[i] = runConnectUDPMultiClientProbeEcho(
				t, pkts[i], echoAddr,
				connectUDPTUNShapeBurstRunBase+uint32(i),
				connectUDPTUNShapeBurstRounds,
			)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("burst flow %d: %v", i, err)
		}
	}
	note := ""
	if layer == "h3" {
		note = " (H3: dedicated QUIC per flow — AUDIT B11 cost)"
	}
	t.Logf("GATE tun-shape-burst %s: N=%d pipeline=1 rounds=%d OK%s",
		layer, connectUDPTUNShapeBurstFlows, connectUDPTUNShapeBurstRounds, note)
}

// gateConnectUDPTUNShapePacedUpload is the SOCKS-loss A/B counterpart without SOCKS:
// paced sequenced upload on CoreSession.ListenPacket (TUN/gvisor uses the same masque
// WriteTo path; ASSOCIATE RCVBUF drops do not apply). Requires zero-loss @ docker paced target.
func gateConnectUDPTUNShapePacedUpload(t *testing.T, layer string) {
	t.Helper()
	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	dur := 2 * time.Second
	target := dockerBenchUDPTargetMbit

	var got connectUDPPacedBenchResult
	switch layer {
	case "h3":
		got = benchConnectUDPPacedSinkGoodput(t, false, dur, target)
	case "h2":
		got = benchConnectUDPH2PacedSinkGoodput(t, false, dur, target)
	default:
		t.Fatalf("unknown layer %q", layer)
	}
	if !got.stats.BurstZeroLossOK(payloadLen, connectudp.DefaultBurstMinRxRatio) {
		t.Fatalf("%s tun-shape paced upload: zero-loss fail rx=%d/%d loss=%.2f%%",
			layer, got.stats.RxPkts, got.sentPkts, got.stats.LossPct)
	}
	minFloor := connectudp.MinPacedGoodputMbit(target) * 0.5
	if got.mbps < minFloor {
		t.Fatalf("%s tun-shape paced goodput %.2f Mbit/s < floor %.2f", layer, got.mbps, minFloor)
	}
	t.Logf("GATE tun-shape %s paced upload: %.2f Mbit/s rx=%d/%d loss=0",
		layer, got.mbps, got.stats.RxPkts, got.sentPkts)
}

func openConnectUDPProdListenPacket(t *testing.T, layer string, echoAddr *net.UDPAddr) (net.PacketConn, func()) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var session ClientSession
	switch layer {
	case "h3":
		proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, p int) {
			registerMasqueUDPProxyHandler(t, mux, p)
		})
		var err error
		session, err = (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
			Server:              "127.0.0.1",
			ServerPort:          uint16(proxyPort),
			PathUDP:             connectUDPInProcessPathUDP,
			MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		})
		if err != nil {
			cancel()
			t.Fatalf("session: %v", err)
		}
	case "h2":
		proxyPort := startInProcessH2UDPConnectProxy(t)
		session, waitCtx = newConnectUDPProdProfileH2SessionWithLink(t, proxyPort, instantH2Link{})
	default:
		cancel()
		t.Fatalf("unknown layer %q", layer)
	}
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		cancel()
		_ = session.Close()
		t.Fatalf("ListenPacket: %v", err)
	}
	cleanup := func() {
		_ = pkt.Close()
		_ = session.Close()
		cancel()
	}
	return pkt, cleanup
}

package masque

// Localize docker connect-udp paced probe: SOCKS5 UDP ASSOCIATE → CONNECT-UDP H3 → sequenced sink.
// Parity with docker/masque-perf-lab bench/udp_masque_send.py + udp_sink_analyze.py.

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

type connectUDPPacedBenchResult struct {
	sentPkts int
	mbps     float64
	stats    connectudp.SequencedStats
}

func benchConnectUDPPacedSinkGoodput(
	t *testing.T,
	viaSocks bool,
	duration time.Duration,
	targetMbit float64,
) connectUDPPacedBenchResult {
	t.Helper()
	const runID = uint32(0xD0C0BEEF)
	payloadLen := connectudp.DefaultBenchUDPPayloadLen

	sinkConn, seqSink := runUDPSequencedSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, runID)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})
	session := startConnectUDPMasqueSession(t, proxyPort)

	var pkt net.PacketConn
	if viaSocks {
		out := &masqueSessionOutbound{
			Adapter: outbound.NewAdapter(C.TypeMasque, "masque-out", []string{N.NetworkTCP, N.NetworkUDP}, nil),
			sess:    session,
		}
		cm := route.NewConnectionManager(log.StdLogger())
		t.Cleanup(func() { _ = cm.Close() })
		router := &directMasqueRouter{cm: cm, dialer: out}
		socksPort := startSocks5AssociateRelay(t, router, C.TypeSOCKS)

		dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", socksPort), socks.Version5, "", "")
		ctx, cancel := context.WithTimeout(context.Background(), duration+5*time.Second)
		t.Cleanup(cancel)
		var err error
		pkt, err = dialer.ListenPacket(ctx, M.ParseSocksaddrHostPort(sinkAddr.IP.String(), uint16(sinkAddr.Port)))
		if err != nil {
			t.Fatalf("socks udp associate listen: %v", err)
		}
		t.Cleanup(func() { _ = pkt.Close() })
	} else {
		waitCtx, cancel := context.WithTimeout(context.Background(), duration+5*time.Second)
		t.Cleanup(cancel)
		var err error
		pkt, err = session.ListenPacket(waitCtx, M.Socksaddr{
			Addr: netip.MustParseAddr(sinkAddr.IP.String()),
			Port: uint16(sinkAddr.Port),
		})
		if err != nil {
			t.Fatalf("ListenPacket: %v", err)
		}
		t.Cleanup(func() { _ = pkt.Close() })
	}

	wallStart := time.Now()
	deadline := wallStart.Add(duration)
	var seq uint64
	var sent int
	var paceSlot time.Time
	for time.Now().Before(deadline) {
		p := connectudp.BuildProbePayload(seq, runID, payloadLen)
		if err := writeToWithStallGuard(t, pkt, p, sinkAddr, connectUDPSynthUploadWriteStall); err != nil {
			t.Fatalf("paced send stalled seq=%d sent=%d: %v", seq, sent, err)
		}
		sent++
		seq++
		connectudp.PaceSleepUntil(&paceSlot, payloadLen, targetMbit)
	}
	time.Sleep(50 * time.Millisecond)
	wall := time.Since(wallStart)
	if wall <= 0 {
		wall = duration
	}
	st := seqSink.Analyze(sent, payloadLen)
	mbps := float64(sent*payloadLen*8) / wall.Seconds() / 1e6
	return connectUDPPacedBenchResult{sentPkts: sent, mbps: mbps, stats: st}
}

// TestLocalizeConnectUDPDockerPacedDirectVsSocks5 localizes docker connect-udp-h3 paced path:
// direct ListenPacket vs SOCKS5 UDP ASSOCIATE (same probe layout as udp_masque_send.py).
func TestLocalizeConnectUDPDockerPacedDirectVsSocks5(t *testing.T) {
	const duration = connectUDPSynthProdBenchDuration
	target := dockerBenchUDPTargetMbit

	direct := benchConnectUDPPacedSinkGoodput(t, false, duration, target)
	socks := benchConnectUDPPacedSinkGoodput(t, true, duration, target)

	assertConnectUDPProbeLoss(t, "direct paced", direct.stats, connectUDPSynthMaxLossPct)
	assertConnectUDPProbeLoss(t, "socks paced", socks.stats, connectUDPSynthMaxLossPct)

	minFloor := connectudp.MinPacedGoodputMbit(target)
	if direct.mbps < minFloor {
		t.Fatalf("direct paced sink goodput %.2f Mbit/s < docker floor %.2f", direct.mbps, minFloor)
	}
	if socks.mbps < minFloor {
		t.Fatalf("socks paced sink goodput %.2f Mbit/s < docker floor %.2f", socks.mbps, minFloor)
	}

	ratio := socks.mbps / direct.mbps
	t.Logf("docker paced localize: direct=%.2f socks=%.2f Mbit/s ratio=%.2f (target %.0f floor %.2f)",
		direct.mbps, socks.mbps, ratio, target, minFloor)

	const maxSocksOverheadRatio = 1.12
	if ratio < 1.0/maxSocksOverheadRatio || ratio > maxSocksOverheadRatio {
		t.Fatalf("socks/direct paced ratio %.2f outside [%.2f, %.2f] — SOCKS path is the docker gap",
			ratio, 1.0/maxSocksOverheadRatio, maxSocksOverheadRatio)
	}
}

// TestLocalizeConnectUDPDockerPacedCompensatedPacing verifies compensated pacing hits docker KPI band in-proc.
func TestLocalizeConnectUDPDockerPacedCompensatedPacing(t *testing.T) {
	const duration = connectUDPSynthProdBenchDuration
	got := benchConnectUDPPacedSinkGoodput(t, false, duration, dockerBenchUDPTargetMbit)
	assertConnectUDPProbeLoss(t, "compensated paced", got.stats, connectUDPSynthMaxLossPct)

	if got.mbps < connectUDPLocalizePacedMinMbps || got.mbps > connectUDPLocalizePacedMaxMbps {
		t.Fatalf("compensated paced goodput %.2f Mbit/s (want %.1f–%.1f @ target %.0f)",
			got.mbps, connectUDPLocalizePacedMinMbps, connectUDPLocalizePacedMaxMbps, dockerBenchUDPTargetMbit)
	}
	t.Logf("compensated paced goodput: %.2f Mbit/s sent=%d rx=%d loss=%.2f%%",
		got.mbps, got.sentPkts, got.stats.RxPkts, got.stats.LossPct)
}

// startConnectUDPH2MasqueSession is the H2 overlay variant of startConnectUDPMasqueSession (docker/synth parity).
func startConnectUDPH2MasqueSession(t *testing.T, proxyPort int) ClientSession {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:                   "127.0.0.1",
		ServerPort:               uint16(proxyPort),
		TransportMode:            option.MasqueTransportModeConnectUDP,
		MasqueEffectiveHTTPLayer: option.MasqueHTTPLayerH2,
		MasqueQUICCryptoTLS:      &tls.Config{InsecureSkipVerify: true},
		TCPDial:                  baseDial,
	})
	if err != nil {
		t.Fatalf("new connect-udp-h2 session: %v", err)
	}
	t.Cleanup(func() { closeConnectUDPTestSession(session) })
	return session
}

// TestLocalizeConnectUDPDockerPacedH2UploadGoodput verifies H2 CONNECT-UDP upload meets docker paced floor in-proc.
func TestLocalizeConnectUDPDockerPacedH2UploadGoodput(t *testing.T) {
	const duration = connectUDPSynthProdBenchDuration
	target := dockerBenchUDPTargetMbit

	sinkConn, seqSink := runUDPSequencedSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, 0xD0C0BEEF)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(t)
	session := startConnectUDPH2MasqueSession(t, proxyPort)

	waitCtx, cancel := context.WithTimeout(context.Background(), duration+5*time.Second)
	t.Cleanup(cancel)
	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket h2: %v", err)
	}
	t.Cleanup(func() { _ = pkt.Close() })

	got := benchConnectUDPPacedSinkGoodputWithPacket(t, pkt, sinkAddr, seqSink, 0xD0C0BEEF, duration, target)
	assertConnectUDPProbeLoss(t, "h2 paced upload", got.stats, connectUDPSynthMaxLossPct)
	minFloor := connectudp.MinPacedGoodputMbit(target)
	if got.mbps < minFloor {
		t.Fatalf("h2 paced upload goodput %.2f Mbit/s < docker floor %.2f", got.mbps, minFloor)
	}
	t.Logf("docker paced h2 upload: %.2f Mbit/s sent=%d rx=%d loss=%.2f%% (floor %.2f)",
		got.mbps, got.sentPkts, got.stats.RxPkts, got.stats.LossPct, minFloor)
}

func benchConnectUDPPacedSinkGoodputWithPacket(
	t *testing.T,
	pkt net.PacketConn,
	sinkAddr *net.UDPAddr,
	seqSink *connectudp.SequencedSink,
	runID uint32,
	duration time.Duration,
	targetMbit float64,
) connectUDPPacedBenchResult {
	t.Helper()
	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	wallStart := time.Now()
	deadline := wallStart.Add(duration)
	var seq uint64
	var sent int
	var paceSlot time.Time
	for time.Now().Before(deadline) {
		p := connectudp.BuildProbePayload(seq, runID, payloadLen)
		if err := writeToWithStallGuard(t, pkt, p, sinkAddr, connectUDPSynthUploadWriteStall); err != nil {
			t.Fatalf("paced send stalled seq=%d sent=%d: %v", seq, sent, err)
		}
		sent++
		seq++
		connectudp.PaceSleepUntil(&paceSlot, payloadLen, targetMbit)
	}
	time.Sleep(50 * time.Millisecond)
	wall := time.Since(wallStart)
	if wall <= 0 {
		wall = duration
	}
	st := seqSink.Analyze(sent, payloadLen)
	mbps := float64(sent*payloadLen*8) / wall.Seconds() / 1e6
	return connectUDPPacedBenchResult{sentPkts: sent, mbps: mbps, stats: st}
}

func benchConnectUDPBurstZeroLossMax(
	t *testing.T,
	httpLayer string,
	viaSocks bool,
	duration time.Duration,
) (float64, connectudp.SequencedStats) {
	t.Helper()
	const baseRunID = uint32(0xD0C00000)
	payloadLen := connectudp.DefaultBenchUDPPayloadLen

	sinkConn, seqSink := runUDPSequencedSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, baseRunID|1)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)

	var session ClientSession
	if httpLayer == option.MasqueHTTPLayerH2 {
		proxyPort := startInProcessH2UDPConnectProxy(t)
		session = startConnectUDPH2MasqueSession(t, proxyPort)
	} else {
		proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
			registerMasqueUDPProxyHandler(t, mux, proxyPort)
		})
		session = startConnectUDPMasqueSession(t, proxyPort)
	}

	var (
		pkt     net.PacketConn
		socksCM *route.ConnectionManager
	)
	if viaSocks {
		out := &masqueSessionOutbound{
			Adapter: outbound.NewAdapter(C.TypeMasque, "masque-out", []string{N.NetworkTCP, N.NetworkUDP}, nil),
			sess:    session,
		}
		socksCM = route.NewConnectionManager(log.StdLogger())
		t.Cleanup(func() { _ = socksCM.Close() })
		router := &directMasqueRouter{cm: socksCM, dialer: out}
		socksPort := startSocks5AssociateRelay(t, router, C.TypeSOCKS)
		dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", socksPort), socks.Version5, "", "")
		ctx, cancel := context.WithTimeout(context.Background(), 10*duration+30*time.Second)
		t.Cleanup(cancel)
		var err error
		pkt, err = dialer.ListenPacket(ctx, M.ParseSocksaddrHostPort(sinkAddr.IP.String(), uint16(sinkAddr.Port)))
		if err != nil {
			t.Fatalf("socks udp associate listen: %v", err)
		}
		route.TuneUDPPacketConn(pkt)
	} else {
		waitCtx, cancel := context.WithTimeout(context.Background(), 10*duration+30*time.Second)
		t.Cleanup(cancel)
		var err error
		pkt, err = session.ListenPacket(waitCtx, M.Socksaddr{
			Addr: netip.MustParseAddr(sinkAddr.IP.String()),
			Port: uint16(sinkAddr.Port),
		})
		if err != nil {
			t.Fatalf("ListenPacket: %v", err)
		}
		route.TuneUDPPacketConn(pkt)
	}
	t.Cleanup(func() { _ = pkt.Close() })

	dropsBefore := connectudp.SnapshotDataplaneDrops()

	var probeN uint32
	probe := func(targetMbit float64) connectudp.SequencedStats {
		probeN++
		runID := baseRunID | probeN
		seqSink.Reset(runID)
		wallStart := time.Now()
		deadline := wallStart.Add(duration)
		var seq uint64
		var sent int
		var paceSlot time.Time
		for time.Now().Before(deadline) {
			p := connectudp.BuildProbePayload(seq, runID, payloadLen)
			if err := writeToWithStallGuard(t, pkt, p, sinkAddr, connectUDPSynthUploadWriteStall); err != nil {
				t.Fatalf("burst probe %.1f Mbit/s stalled seq=%d sent=%d: %v", targetMbit, seq, sent, err)
			}
			sent++
			seq++
			if targetMbit > 0 {
				connectudp.PaceSleepUntil(&paceSlot, payloadLen, targetMbit)
			}
		}
		connectudp.FlushPacketConnWrites(pkt)
		time.Sleep(500 * time.Millisecond)
		return seqSink.Analyze(sent, payloadLen)
	}

	pass := func(st connectudp.SequencedStats) bool {
		return st.BurstZeroLossOK(payloadLen, connectudp.DefaultBurstMinRxRatio)
	}

	lo, hi := 8.0, 500.0
	var best connectudp.SequencedStats
	var bestMbps float64
	for step := 0; step < 10; step++ {
		mid := (lo + hi) / 2
		st := probe(mid)
		t.Logf("burst zero-loss search %d: target=%.1f Mbps loss=%.2f%% dup=%.2f%% ooo=%d rx=%d/%d excess=%d socks=%v",
			step+1, mid, st.LossPct, st.DupPct, st.OOOPkts, st.RxPkts, st.SentPkts, st.ExcessPkts, viaSocks)
		if pass(st) {
			lo = mid
			best = st
			bestMbps = mid
		} else {
			hi = mid
		}
		if hi-lo < 4 {
			break
		}
	}
	for step := bestMbps + 4; step <= hi+4; step += 4 {
		st := probe(step)
		t.Logf("burst zero-loss refine: target=%.1f Mbps loss=%.2f%% dup=%.2f%% ooo=%d rx=%d/%d excess=%d",
			step, st.LossPct, st.DupPct, st.OOOPkts, st.RxPkts, st.SentPkts, st.ExcessPkts)
		if pass(st) {
			best = st
			bestMbps = step
		} else {
			break
		}
	}
	if dropDelta := connectudp.SnapshotDataplaneDrops().Delta(dropsBefore); dropDelta.HasDrops() {
		t.Fatalf("dataplane drops during burst search: %+v", dropDelta)
	}
	return bestMbps, best
}

// TestLocalizeConnectUDPDockerBurstDirectVsSocks5 localizes max zero-loss burst (docker burst KPI shape).
func TestLocalizeConnectUDPDockerBurstDirectVsSocks5(t *testing.T) {
	const duration = connectUDPSynthProdBenchDuration

	directMbps, directSt := benchConnectUDPBurstZeroLossMax(t, option.MasqueHTTPLayerH3, false, duration)
	socksMbps, socksSt := benchConnectUDPBurstZeroLossMax(t, option.MasqueHTTPLayerH3, true, duration)

	t.Logf("docker burst zero-loss h3: direct=%.1f socks=%.1f Mbit/s (rx %d/%d vs %d/%d)",
		directMbps, socksMbps, directSt.RxPkts, directSt.SentPkts, socksSt.RxPkts, socksSt.SentPkts)

	if !directSt.BurstZeroLossOK(connectudp.DefaultBenchUDPPayloadLen, connectudp.DefaultBurstMinRxRatio) {
		t.Fatalf("direct burst best probe failed zero-loss gate: %+v", directSt)
	}
	if !socksSt.BurstZeroLossOK(connectudp.DefaultBenchUDPPayloadLen, connectudp.DefaultBurstMinRxRatio) {
		t.Fatalf("socks burst best probe failed zero-loss gate: %+v", socksSt)
	}

	if directMbps < 80 {
		t.Fatalf("direct max zero-loss burst %.1f < 80 Mbit/s", directMbps)
	}
	if socksMbps < 80 {
		t.Fatalf("socks max zero-loss burst %.1f < 80 Mbit/s", socksMbps)
	}
	ratio := socksMbps / directMbps
	const minBurstSocksDirectRatio = 0.40
	if ratio < minBurstSocksDirectRatio {
		t.Fatalf("socks/direct burst zero-loss ratio %.2f < %.2f — SOCKS burst regression",
			ratio, minBurstSocksDirectRatio)
	}
	if ratio < 0.85 {
		t.Logf("NOTE: burst SOCKS overhead ~%.0f%% of direct (paced guard is ~1.0); optimize SOCKS/dataplane toward 0.85",
			ratio*100)
	}
}

// TestLocalizeConnectUDPDockerBurstH2DirectVsSocks5 localizes H2 max zero-loss burst (docker burst KPI shape).
func TestLocalizeConnectUDPDockerBurstH2DirectVsSocks5(t *testing.T) {
	const duration = connectUDPSynthProdBenchDuration

	directMbps, directSt := benchConnectUDPBurstZeroLossMax(t, option.MasqueHTTPLayerH2, false, duration)
	socksMbps, socksSt := benchConnectUDPBurstZeroLossMax(t, option.MasqueHTTPLayerH2, true, duration)

	t.Logf("docker burst zero-loss h2: direct=%.1f socks=%.1f Mbit/s (rx %d/%d vs %d/%d)",
		directMbps, socksMbps, directSt.RxPkts, directSt.SentPkts, socksSt.RxPkts, socksSt.SentPkts)

	if !directSt.BurstZeroLossOK(connectudp.DefaultBenchUDPPayloadLen, connectudp.DefaultBurstMinRxRatio) {
		t.Fatalf("h2 direct burst best probe failed zero-loss gate: %+v", directSt)
	}
	if !socksSt.BurstZeroLossOK(connectudp.DefaultBenchUDPPayloadLen, connectudp.DefaultBurstMinRxRatio) {
		t.Fatalf("h2 socks burst best probe failed zero-loss gate: %+v", socksSt)
	}

	const minDockerBurstMbps = 500.0
	if directMbps < minDockerBurstMbps {
		t.Fatalf("h2 direct max zero-loss burst %.1f < %.0f Mbit/s", directMbps, minDockerBurstMbps)
	}
	if socksMbps < minDockerBurstMbps {
		t.Fatalf("h2 socks max zero-loss burst %.1f < %.0f Mbit/s (Docker uses SOCKS5 ASSOCIATE; in-proc direct=%.1f)",
			socksMbps, minDockerBurstMbps, directMbps)
	}
	ratio := socksMbps / directMbps
	if ratio < 0.85 {
		t.Fatalf("h2 socks/direct burst ratio %.2f < 0.85", ratio)
	}
}

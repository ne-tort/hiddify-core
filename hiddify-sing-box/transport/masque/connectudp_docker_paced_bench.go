package masque

// Docker-paced CONNECT-UDP bench helpers (W-UDP-4 inttest MOVE).
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
	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

type connectUDPPacedBenchResult struct {
	sentPkts int
	mbps     float64
	stats    connectudp.SequencedStats
}

type connectUDPBurstProbeResult struct {
	target   float64
	stats    connectudp.SequencedStats
	wallSec  float64
	achieved float64
}

// finishConnectUDPPacedProbeUpload drains masque upload after paced send (direct or SOCKS relay).
func finishConnectUDPPacedProbeUpload(pkt net.PacketConn, viaSocks bool) {
	connectudp.FlushPacketConnWrites(pkt)
	if viaSocks {
		// Keep SOCKS associate open while sharded H2 async upload drains (closing early drops in-flight).
		time.Sleep(2 * time.Second)
		return
	}
	_ = connectudp.DrainPacketConnUpload(pkt, connectudp.DefaultUploadDrainTimeout)
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
	t.Cleanup(func() {
		if pkt != nil {
			_ = pkt.Close()
		}
	})
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
	}
	route.TuneUDPPacketConn(pkt)

	wallStart := time.Now()
	deadline := wallStart.Add(duration)
	var seq uint64
	var sent int
	var paceSlot time.Time
	for time.Now().Before(deadline) {
		p := connectudp.BuildProbePayload(seq, runID, payloadLen)
		if _, err := pkt.WriteTo(p, sinkAddr); err != nil {
			t.Fatalf("paced send seq=%d sent=%d: %v", seq, sent, err)
		}
		sent++
		seq++
		connectudp.PaceSleepUntil(&paceSlot, payloadLen, targetMbit)
	}
	sendWall := time.Since(wallStart)
	finishConnectUDPPacedProbeUpload(pkt, viaSocks)
	time.Sleep(50 * time.Millisecond)
	wall := sendWall
	if wall <= 0 {
		wall = duration
	}
	st := seqSink.Analyze(sent, payloadLen)
	mbps := float64(sent*payloadLen*8) / wall.Seconds() / 1e6
	return connectUDPPacedBenchResult{sentPkts: sent, mbps: mbps, stats: st}
}

// startConnectUDPH2MasqueSession is the H2 overlay variant of startConnectUDPMasqueSession (docker/synth parity).
func startConnectUDPH2MasqueSession(t *testing.T, proxyPort int) ClientSession {
	t.Helper()
	return startConnectUDPH2MasqueSessionWithLink(t, proxyPort, instantH2Link{})
}

// startConnectUDPH2MasqueSessionWithLink wraps TCP dial with h2TransportLink (tls-flush tax localize).
func startConnectUDPH2MasqueSessionWithLink(t *testing.T, proxyPort int, link h2TransportLink) ClientSession {
	t.Helper()
	if link == nil {
		link = instantH2Link{}
	}
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
		TCPDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := baseDial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if tc, ok := conn.(*net.TCPConn); ok {
				cudprelay.TuneMasqueTCPSocketBuffers(tc)
			}
			return link.wrapTCP(conn), nil
		},
	})
	if err != nil {
		t.Fatalf("new connect-udp-h2 session: %v", err)
	}
	t.Cleanup(func() { closeConnectUDPTestSession(session) })
	return session
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
		if _, err := pkt.WriteTo(p, sinkAddr); err != nil {
			t.Fatalf("paced send seq=%d sent=%d: %v", seq, sent, err)
		}
		sent++
		seq++
		connectudp.PaceSleepUntil(&paceSlot, payloadLen, targetMbit)
	}
	sendWall := time.Since(wallStart)
	finishConnectUDPPacedProbeUpload(pkt, false)
	time.Sleep(50 * time.Millisecond)
	wall := sendWall
	if wall <= 0 {
		wall = duration
	}
	st := seqSink.Analyze(sent, payloadLen)
	mbps := float64(sent*payloadLen*8) / wall.Seconds() / 1e6
	return connectUDPPacedBenchResult{sentPkts: sent, mbps: mbps, stats: st}
}

func benchConnectUDPH2PacedSinkGoodput(
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

	proxyPort := startInProcessH2UDPConnectProxy(t)
	session := startConnectUDPH2MasqueSession(t, proxyPort)

	var pkt net.PacketConn
	t.Cleanup(func() {
		if pkt != nil {
			_ = pkt.Close()
		}
	})
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
		ctx, cancel := context.WithTimeout(context.Background(), duration+10*time.Second)
		t.Cleanup(cancel)
		var err error
		pkt, err = dialer.ListenPacket(ctx, M.ParseSocksaddrHostPort(sinkAddr.IP.String(), uint16(sinkAddr.Port)))
		if err != nil {
			t.Fatalf("socks udp associate listen: %v", err)
		}
	} else {
		waitCtx, cancel := context.WithTimeout(context.Background(), duration+10*time.Second)
		t.Cleanup(cancel)
		var err error
		pkt, err = session.ListenPacket(waitCtx, M.Socksaddr{
			Addr: netip.MustParseAddr(sinkAddr.IP.String()),
			Port: uint16(sinkAddr.Port),
		})
		if err != nil {
			t.Fatalf("ListenPacket h2: %v", err)
		}
	}
	route.TuneUDPPacketConn(pkt)

	wallStart := time.Now()
	deadline := wallStart.Add(duration)
	var seq uint64
	var sent int
	var paceSlot time.Time
	for time.Now().Before(deadline) {
		p := connectudp.BuildProbePayload(seq, runID, payloadLen)
		if _, err := pkt.WriteTo(p, sinkAddr); err != nil {
			t.Fatalf("paced send seq=%d sent=%d: %v", seq, sent, err)
		}
		sent++
		seq++
		connectudp.PaceSleepUntil(&paceSlot, payloadLen, targetMbit)
	}
	sendWall := time.Since(wallStart)
	finishConnectUDPPacedProbeUpload(pkt, viaSocks)
	time.Sleep(50 * time.Millisecond)
	wall := sendWall
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
	return benchConnectUDPBurstZeroLossMaxEx(t, httpLayer, viaSocks, duration, connectudp.DefaultBenchUDPPayloadLen, instantH2Link{})
}

func benchConnectUDPH2BurstZeroLossMax(
	t *testing.T,
	link h2TransportLink,
	viaSocks bool,
	duration time.Duration,
	payloadLen int,
) (float64, connectudp.SequencedStats) {
	t.Helper()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	return benchConnectUDPBurstZeroLossMaxEx(t, option.MasqueHTTPLayerH2, viaSocks, duration, payloadLen, link)
}

func benchConnectUDPBurstZeroLossMaxEx(
	t *testing.T,
	httpLayer string,
	viaSocks bool,
	duration time.Duration,
	payloadLen int,
	h2Link h2TransportLink,
) (float64, connectudp.SequencedStats) {
	t.Helper()
	const baseRunID = uint32(0xD0C00000)
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}

	sinkConn, seqSink := runUDPSequencedSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, baseRunID|1)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)

	var session ClientSession
	if httpLayer == option.MasqueHTTPLayerH2 {
		proxyPort := startInProcessH2UDPConnectProxy(t)
		if h2Link == nil {
			h2Link = instantH2Link{}
		}
		session = startConnectUDPH2MasqueSessionWithLink(t, proxyPort, h2Link)
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
	probe := func(targetMbit float64) connectUDPBurstProbeResult {
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
		sendSec := time.Since(wallStart).Seconds()
		if sendSec <= 0 {
			sendSec = duration.Seconds()
		}
		connectudp.FlushPacketConnWrites(pkt)
		if err := connectudp.DrainPacketConnUpload(pkt, connectudp.DefaultUploadDrainTimeout); err != nil {
			t.Fatalf("burst probe %.1f Mbit/s upload drain: %v", targetMbit, err)
		}
		time.Sleep(500 * time.Millisecond)
		st := seqSink.Analyze(sent, payloadLen)
		achieved := connectudp.BurstSinkGoodputMbit(st.RxPkts, payloadLen, sendSec)
		return connectUDPBurstProbeResult{target: targetMbit, stats: st, wallSec: sendSec, achieved: achieved}
	}

	pass := func(bp connectUDPBurstProbeResult) bool {
		return bp.stats.BurstZeroLossOK(payloadLen, connectudp.DefaultBurstMinRxRatio)
	}

	lo, hi := 8.0, 500.0
	var best connectUDPBurstProbeResult
	var bestAchieved float64
	for step := 0; step < 10; step++ {
		mid := (lo + hi) / 2
		bp := probe(mid)
		t.Logf("burst zero-loss search %d: target=%.1f achieved=%.1f Mbps loss=%.2f%% dup=%.2f%% ooo=%d rx=%d/%d excess=%d socks=%v",
			step+1, mid, bp.achieved, bp.stats.LossPct, bp.stats.DupPct, bp.stats.OOOPkts, bp.stats.RxPkts, bp.stats.SentPkts, bp.stats.ExcessPkts, viaSocks)
		if pass(bp) {
			lo = mid
			if bp.achieved > bestAchieved {
				bestAchieved = bp.achieved
				best = bp
			}
		} else {
			hi = mid
		}
		if hi-lo < 4 {
			break
		}
	}
	for step := lo + 4; step <= hi+4; step += 4 {
		bp := probe(step)
		t.Logf("burst zero-loss refine: target=%.1f achieved=%.1f Mbps loss=%.2f%% dup=%.2f%% ooo=%d rx=%d/%d excess=%d",
			step, bp.achieved, bp.stats.LossPct, bp.stats.DupPct, bp.stats.OOOPkts, bp.stats.RxPkts, bp.stats.SentPkts, bp.stats.ExcessPkts)
		if pass(bp) {
			if bp.achieved > bestAchieved {
				bestAchieved = bp.achieved
				best = bp
			}
		} else {
			break
		}
	}
	bestMbps := bestAchieved
	if dropDelta := connectudp.SnapshotDataplaneDrops().Delta(dropsBefore); dropDelta.HasDrops() {
		t.Fatalf("dataplane drops during burst search: %+v", dropDelta)
	}
	return bestMbps, best.stats
}

// benchConnectUDPH2BurstZeroLossMaxWritePacket sends via bufio WritePacket (prod SOCKS relay entry, no TCP).
func benchConnectUDPH2BurstZeroLossMaxWritePacket(t *testing.T, duration time.Duration) (float64, connectudp.SequencedStats) {
	t.Helper()
	const baseRunID = uint32(0xD0C20000)
	payloadLen := connectudp.DefaultBenchUDPPayloadLen

	sinkConn, seqSink := runUDPSequencedSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, baseRunID|1)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)
	dest := M.ParseSocksaddrHostPort(sinkAddr.IP.String(), uint16(sinkAddr.Port))

	proxyPort := startInProcessH2UDPConnectProxy(t)
	session := startConnectUDPH2MasqueSession(t, proxyPort)
	waitCtx, cancel := context.WithTimeout(context.Background(), 10*duration+30*time.Second)
	t.Cleanup(cancel)
	raw, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	pkt := bufio.NewPacketConn(raw)
	route.TuneUDPPacketConn(pkt)
	pw, ok := pkt.(interface {
		WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error
	})
	if !ok {
		t.Fatal("expected WritePacket on bufio-wrapped H2 ListenPacket")
	}

	var probeN uint32
	probe := func(targetMbit float64) connectUDPBurstProbeResult {
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
			if err := writePacketWithStallGuard(t, pkt, pw, p, dest, connectUDPSynthUploadWriteStall); err != nil {
				t.Fatalf("writepacket burst probe %.1f Mbit/s stalled seq=%d sent=%d: %v", targetMbit, seq, sent, err)
			}
			sent++
			seq++
			if targetMbit > 0 {
				connectudp.PaceSleepUntil(&paceSlot, payloadLen, targetMbit)
			}
		}
		sendSec := time.Since(wallStart).Seconds()
		if sendSec <= 0 {
			sendSec = duration.Seconds()
		}
		connectudp.FlushPacketConnWrites(pkt)
		if err := connectudp.DrainPacketConnUpload(pkt, connectudp.DefaultUploadDrainTimeout); err != nil {
			t.Fatalf("burst probe %.1f Mbit/s upload drain: %v", targetMbit, err)
		}
		time.Sleep(500 * time.Millisecond)
		st := seqSink.Analyze(sent, payloadLen)
		achieved := connectudp.BurstSinkGoodputMbit(st.RxPkts, payloadLen, sendSec)
		return connectUDPBurstProbeResult{target: targetMbit, stats: st, wallSec: sendSec, achieved: achieved}
	}

	pass := func(bp connectUDPBurstProbeResult) bool {
		return bp.stats.BurstZeroLossOK(payloadLen, connectudp.DefaultBurstMinRxRatio)
	}

	lo, hi := 8.0, 500.0
	var best connectUDPBurstProbeResult
	var bestAchieved float64
	for step := 0; step < 10; step++ {
		mid := (lo + hi) / 2
		bp := probe(mid)
		t.Logf("h2 writepacket burst search %d: target=%.1f achieved=%.1f Mbps loss=%.2f%% rx=%d/%d",
			step+1, mid, bp.achieved, bp.stats.LossPct, bp.stats.RxPkts, bp.stats.SentPkts)
		if pass(bp) {
			lo = mid
			if bp.achieved > bestAchieved {
				bestAchieved = bp.achieved
				best = bp
			}
		} else {
			hi = mid
		}
		if hi-lo < 4 {
			break
		}
	}
	return bestAchieved, best.stats
}

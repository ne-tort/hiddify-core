package masque

// GATE-CONNECT-UDP-STABILITY: no stream/datagram stalls, sequenced loss tracking (docker probe parity).

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

func assertConnectUDPProbeLoss(t *testing.T, leg string, st connectudp.SequencedStats, maxLossPct float64) {
	t.Helper()
	if !st.FillIntegrityOK(connectudp.DefaultBenchUDPPayloadLen) {
		t.Fatalf("%s: fill_sha256 integrity fail rx=%d sent=%d hash=%s",
			leg, st.RxPkts, st.SentPkts, st.FillSHA256)
	}
	if st.LossPct > maxLossPct {
		t.Fatalf("%s: loss %.2f%% (%d/%d pkts) > %.1f%% — packet loss is a code defect, not environment",
			leg, st.LossPct, st.LossPkts, st.SentPkts, maxLossPct)
	}
	t.Logf("%s stability: sent=%d rx=%d loss=%.2f%% dup=%.2f%% ooo=%d",
		leg, st.SentPkts, st.RxPkts, st.LossPct, st.DupPct, st.OOOPkts)
}

func newConnectUDPH3ProdListenPacket(tb testing.TB, target M.Socksaddr) (net.PacketConn, func()) {
	return newConnectUDPH3ProdListenPacketWithRegister(tb, target, registerMasqueUDPProxyHandler)
}

func newConnectUDPH3ProdListenPacketWithRegister(
	tb testing.TB,
	target M.Socksaddr,
	register func(testing.TB, *http.ServeMux, int),
) (net.PacketConn, func()) {
	tb.Helper()
	waitCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	proxyPort := startInProcessMasqueUDPProxy(tb, func(mux *http.ServeMux, proxyPort int) {
		register(tb, mux, proxyPort)
	})
	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		TransportMode:       option.MasqueTransportModeConnectUDP,
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		cancel()
		tb.Fatalf("session: %v", err)
	}
	pkt, err := session.ListenPacket(waitCtx, target)
	if err != nil {
		_ = session.Close()
		cancel()
		tb.Fatalf("ListenPacket: %v", err)
	}
	cleanup := func() {
		_ = pkt.Close()
		_ = session.Close()
		cancel()
	}
	tb.Cleanup(cleanup)
	return pkt, cleanup
}

// TestGATEConnectUDPH3SynthStabilityUploadPaced locks paced upload @ docker 8 Mbit/s with sequenced loss gate.
func TestGATEConnectUDPH3SynthStabilityUploadPaced(t *testing.T) {
	const runID = uint32(0xC0FFEE01)
	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	sinkConn, seqSink := runUDPSequencedSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, runID)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)

	pkt, _ := newConnectUDPH3ProdListenPacket(t, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})

	wallStart := time.Now()
	benchDur := connectUDPSynthProdBenchDuration
	deadline := time.Now().Add(benchDur)
	var seq uint64
	var sent int
	var paceSlot time.Time
	for time.Now().Before(deadline) {
		p := connectudp.BuildProbePayload(seq, runID, payloadLen)
		if err := writeToWithStallGuard(t, pkt, p, sinkAddr, connectUDPSynthUploadWriteStall); err != nil {
			t.Fatalf("paced upload stalled at seq=%d after %d pkts: %v", seq, sent, err)
		}
		sent++
		seq++
		connectudp.PaceSleepUntil(&paceSlot, payloadLen, dockerBenchUDPTargetMbit)
	}
	wall := time.Since(wallStart)
	if wall > benchDur+connectUDPSynthStabilityWallSlack {
		t.Fatalf("paced upload wall %v > bench %v + slack %v (scheduler stall?)",
			wall, benchDur, connectUDPSynthStabilityWallSlack)
	}
	time.Sleep(50 * time.Millisecond) // drain sink goroutine
	st := seqSink.Analyze(sent, payloadLen)
	assertConnectUDPProbeLoss(t, "paced upload", st, connectUDPSynthMaxLossPct)
}

// TestLocalizeConnectUDPH3BurstMaxZeroLossMbps finds max paced burst with 0% sequenced loss (Docker parity).
func TestLocalizeConnectUDPH3BurstMaxZeroLossMbps(t *testing.T) {
	const baseRunID = uint32(0xC0FF0000)
	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	sinkConn, seqSink := runUDPSequencedSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, baseRunID|1)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)

	pkt, _ := newConnectUDPH3ProdListenPacket(t, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})
	route.TuneUDPPacketConn(pkt)

	dropsBefore := connectudp.SnapshotDataplaneDrops()

	var probeN uint32
	probe := func(targetMbit float64) connectudp.SequencedStats {
		probeN++
		runID := baseRunID | probeN
		seqSink.Reset(runID)
		wallStart := time.Now()
		deadline := wallStart.Add(connectUDPSynthProdBenchDuration)
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

	lo, hi := 8.0, 400.0
	var best connectudp.SequencedStats
	var bestMbps float64
	for step := 0; step < 9; step++ {
		mid := (lo + hi) / 2
		st := probe(mid)
		t.Logf("burst zero-loss search %d: target=%.1f Mbps loss=%.2f%% dup=%.2f%% rx=%d/%d excess=%d",
			step+1, mid, st.LossPct, st.DupPct, st.RxPkts, st.SentPkts, st.ExcessPkts)
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
	if dropDelta := connectudp.SnapshotDataplaneDrops().Delta(dropsBefore); dropDelta.HasDrops() {
		t.Fatalf("dataplane drops during burst search: %+v", dropDelta)
	}
	if !best.BurstZeroLossOK(payloadLen, connectudp.DefaultBurstMinRxRatio) {
		t.Fatalf("best probe failed zero-loss gate: %+v", best)
	}
	if bestMbps < 80 {
		t.Fatalf("max zero-loss burst %.1f Mbit/s < 80 floor (loss=%.2f%%)", bestMbps, best.LossPct)
	}
	t.Logf("max zero-loss burst: %.1f Mbit/s (rx=%d/%d)", bestMbps, best.RxPkts, best.SentPkts)
}

// TestGATEConnectUDPH3SynthStabilityUploadSustained ensures unlimited 2s upload completes without WriteTo hang.
func TestGATEConnectUDPH3SynthStabilityUploadSustained(t *testing.T) {
	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	sink, rxBytes := runUDPSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	pkt, _ := newConnectUDPH3ProdListenPacket(t, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})

	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	wallStart := time.Now()
	benchDur := connectUDPSynthProdBenchDuration
	deadline := time.Now().Add(benchDur)
	var sent int
	for time.Now().Before(deadline) {
		if err := writeToWithStallGuard(t, pkt, payload, sinkAddr, connectUDPSynthUploadWriteStall); err != nil {
			t.Fatalf("sustained upload stalled after %d pkts in %v: %v",
				sent, time.Since(wallStart), err)
		}
		sent++
	}
	wall := time.Since(wallStart)
	if wall > benchDur+connectUDPSynthStabilityWallSlack {
		t.Fatalf("sustained upload wall %v > bench %v + slack %v", wall, benchDur, connectUDPSynthStabilityWallSlack)
	}
	if sent == 0 {
		t.Fatal("sustained upload sent 0 packets")
	}
	time.Sleep(50 * time.Millisecond)
	t.Logf("sustained upload: sent=%d pkts rx_bytes=%d (discard sink, hang check only)", sent, rxBytes.Load())
}

// TestGATEConnectUDPH3SynthIntegrityEcho verifies sequenced round-trip on echo path (no loss at single-packet scale).
func TestGATEConnectUDPH3SynthIntegrityEcho(t *testing.T) {
	const (
		runID      = uint32(0xC0FFEE03)
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
		rounds     = 64
	)
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	pkt, _ := newConnectUDPH3ProdListenPacket(t, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})

	buf := make([]byte, payloadLen+64)
	for seq := range uint64(rounds) {
		p := connectudp.BuildProbePayload(seq, runID, payloadLen)
		if err := writeToWithStallGuard(t, pkt, p, echoAddr, connectUDPSynthUploadWriteStall); err != nil {
			t.Fatalf("echo write seq=%d: %v", seq, err)
		}
		readDone := make(chan error, 1)
		go func(seq uint64) {
			readDone <- readProbeWithStallGuard(t, pkt, buf, runID, seq, connectUDPSynthUploadWriteStall)
		}(seq)
		select {
		case err := <-readDone:
			if err != nil {
				t.Fatalf("echo read seq=%d: %v", seq, err)
			}
		case <-time.After(connectUDPSynthUploadWriteStall):
			t.Fatalf("echo ReadFrom stalled >%v at seq=%d", connectUDPSynthUploadWriteStall, seq)
		}
	}
	t.Logf("integrity echo: %d sequenced round-trips OK", rounds)
}

// TestGATEConnectUDPH3SynthStabilityDuplexEcho runs paced upload on sink + sequenced echo on parallel session.
func TestGATEConnectUDPH3SynthStabilityDuplexEcho(t *testing.T) {
	const (
		uploadRunID = uint32(0xC0FFEE04)
		echoRunID   = uint32(0xC0FFEE05)
		payloadLen  = connectudp.DefaultBenchUDPPayloadLen
	)
	sinkConn, _ := runUDPSequencedSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, uploadRunID)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	uploadPkt, _ := newConnectUDPH3ProdListenPacket(t, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})
	echoPkt, _ := newConnectUDPH3ProdListenPacket(t, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})

	benchDur := connectUDPSynthProdBenchDuration
	stop := make(chan struct{})
	uploadErr := make(chan error, 1)
	go func() {
		var seq uint64
		var paceSlot time.Time
		for {
			select {
			case <-stop:
				uploadErr <- nil
				return
			default:
				p := connectudp.BuildProbePayload(seq, uploadRunID, payloadLen)
				if err := writeToWithStallGuard(t, uploadPkt, p, sinkAddr, connectUDPSynthUploadWriteStall); err != nil {
					uploadErr <- err
					return
				}
				seq++
				connectudp.PaceSleepUntil(&paceSlot, payloadLen, dockerBenchUDPTargetMbit)
			}
		}
	}()

	buf := make([]byte, payloadLen+64)
	echoDeadline := time.Now().Add(benchDur)
	var echoOK int
	for time.Now().Before(echoDeadline) {
		p := connectudp.BuildProbePayload(uint64(echoOK), echoRunID, payloadLen)
		if err := writeToWithStallGuard(t, echoPkt, p, echoAddr, connectUDPSynthUploadWriteStall); err != nil {
			close(stop)
			t.Fatalf("duplex echo write: %v", err)
		}
		if err := readProbeWithStallGuard(t, echoPkt, buf, echoRunID, uint64(echoOK), connectUDPSynthUploadWriteStall); err != nil {
			close(stop)
			t.Fatalf("duplex echo read seq=%d: %v", echoOK, err)
		}
		echoOK++
	}
	close(stop)
	select {
	case err := <-uploadErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(connectUDPSynthUploadWriteStall):
		t.Fatalf("duplex upload goroutine did not exit after stop")
	}
	if echoOK < 8 {
		t.Fatalf("duplex echo only %d round-trips in %v (parallel session stall?)", echoOK, benchDur)
	}
	t.Logf("duplex stability: echo_round_trips=%d over %v with paced parallel upload", echoOK, benchDur)
}

package masque

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

func InttestGATEConnectUDPH3SynthStabilityUploadPaced(t *testing.T) {
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
	time.Sleep(50 * time.Millisecond)
	st := seqSink.Analyze(sent, payloadLen)
	assertConnectUDPProbeLoss(t, "paced upload", st, connectUDPSynthMaxLossPct)
}

func InttestLocalizeConnectUDPH3BurstMaxZeroLossMbps(t *testing.T) {
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
	probe := func(targetMbit float64) (connectudp.SequencedStats, float64) {
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
		sendSec := time.Since(wallStart).Seconds()
		if sendSec <= 0 {
			sendSec = connectUDPSynthProdBenchDuration.Seconds()
		}
		connectudp.FlushPacketConnWrites(pkt)
		if err := connectudp.DrainPacketConnUpload(pkt, connectudp.DefaultUploadDrainTimeout); err != nil {
			t.Fatalf("burst probe %.1f Mbit/s upload drain: %v", targetMbit, err)
		}
		time.Sleep(500 * time.Millisecond)
		st := seqSink.Analyze(sent, payloadLen)
		achieved := connectudp.BurstSinkGoodputMbit(st.RxPkts, payloadLen, sendSec)
		return st, achieved
	}

	pass := func(st connectudp.SequencedStats) bool {
		return st.BurstZeroLossOK(payloadLen, connectudp.DefaultBurstMinRxRatio)
	}

	lo, hi := 8.0, 400.0
	var best connectudp.SequencedStats
	var bestMbps float64
	for step := 0; step < 9; step++ {
		mid := (lo + hi) / 2
		st, achieved := probe(mid)
		t.Logf("burst zero-loss search %d: target=%.1f achieved=%.1f Mbps loss=%.2f%% dup=%.2f%% rx=%d/%d excess=%d",
			step+1, mid, achieved, st.LossPct, st.DupPct, st.RxPkts, st.SentPkts, st.ExcessPkts)
		if pass(st) {
			lo = mid
			if achieved > bestMbps {
				bestMbps = achieved
				best = st
			}
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

func InttestGATEConnectUDPH3SynthStabilityUploadSustained(t *testing.T) {
	payloadLen := connectudp.DefaultBenchUDPPayloadLen
	sink, rxBytes := runUDPSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	pkt, _ := newConnectUDPH3ProdListenPacket(t, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})

	wallStart := time.Now()
	benchDur := connectUDPSynthProdBenchDuration
	bytes, mbps, err := benchConnectUDPPacketUpload(t, pkt, sinkAddr, benchDur, 0, payloadLen)
	if err != nil {
		t.Fatalf("sustained upload failed after %v: %v", time.Since(wallStart), err)
	}
	wall := time.Since(wallStart)
	if wall > benchDur+connectUDPSynthStabilityWallSlack {
		t.Fatalf("sustained upload wall %v > bench %v + slack %v", wall, benchDur, connectUDPSynthStabilityWallSlack)
	}
	if bytes == 0 {
		t.Fatal("sustained upload sent 0 bytes")
	}
	time.Sleep(50 * time.Millisecond)
	t.Logf("sustained upload: bytes=%d mbps=%.1f rx_bytes=%d (discard sink, hang check only)", bytes, mbps, rxBytes.Load())
}

func InttestGATEConnectUDPH3SynthIntegrityEcho(t *testing.T) {
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

func InttestGATEConnectUDPH3SynthStabilityDuplexEcho(t *testing.T) {
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

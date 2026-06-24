package masque

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

// benchConnectUDPH2ParallelSessionsUpload floods the sink from N independent H2 sessions (N TCP pools).
func benchConnectUDPH2ParallelSessionsUpload(
	t *testing.T,
	parallel int,
	link h2TransportLink,
	duration time.Duration,
	payloadLen int,
	targetMbit float64,
) (goodputMbps float64, stats connectudp.SequencedStats, totalSent int) {
	t.Helper()
	if parallel < 1 {
		parallel = 1
	}
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	const baseRunID = uint32(0xD0D10000)

	sinkConn, seqSink := runUDPSequencedSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, baseRunID|1)
	sinkAddr := sinkConn.LocalAddr().(*net.UDPAddr)
	proxyPort := startInProcessH2UDPConnectProxy(t)

	pkts := make([]net.PacketConn, parallel)
	for i := 0; i < parallel; i++ {
		session := startConnectUDPH2MasqueSessionWithLink(t, proxyPort, link)
		waitCtx, cancel := context.WithTimeout(context.Background(), 10*duration+30*time.Second)
		t.Cleanup(cancel)
		pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
			Addr: netip.MustParseAddr(sinkAddr.IP.String()),
			Port: uint16(sinkAddr.Port),
		})
		if err != nil {
			t.Fatalf("ListenPacket parallel=%d: %v", i, err)
		}
		t.Cleanup(func() { _ = pkt.Close() })
		pkts[i] = pkt
	}

	perWorkerTarget := targetMbit
	if targetMbit > 0 {
		perWorkerTarget = targetMbit / float64(parallel)
	}

	wallStart := time.Now()
	deadline := wallStart.Add(duration)
	sentPerWorker := make([]int, parallel)
	var wg sync.WaitGroup
	for w := 0; w < parallel; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			pkt := pkts[worker]
			var seq uint64 = uint64(worker)
			var paceSlot time.Time
			for time.Now().Before(deadline) {
				p := connectudp.BuildProbePayload(seq, baseRunID|1, payloadLen)
				if err := writeToWithStallGuard(t, pkt, p, sinkAddr, connectUDPSynthUploadWriteStall); err != nil {
					t.Errorf("parallel=%d worker=%d stalled seq=%d: %v", parallel, worker, seq, err)
					return
				}
				sentPerWorker[worker]++
				seq += uint64(parallel)
				if perWorkerTarget > 0 {
					connectudp.PaceSleepUntil(&paceSlot, payloadLen, perWorkerTarget)
				}
			}
		}(w)
	}
	wg.Wait()
	for _, pkt := range pkts {
		connectudp.FlushPacketConnWrites(pkt)
		if err := connectudp.DrainPacketConnUpload(pkt, connectudp.DefaultUploadDrainTimeout); err != nil {
			t.Fatalf("parallel=%d upload drain: %v", parallel, err)
		}
	}
	time.Sleep(500 * time.Millisecond)

	for _, n := range sentPerWorker {
		totalSent += n
	}
	wallSec := time.Since(wallStart).Seconds()
	if wallSec <= 0 {
		wallSec = duration.Seconds()
	}
	st := seqSink.Analyze(totalSent, payloadLen)
	goodputMbps = connectudp.BurstSinkGoodputMbit(st.RxPkts, payloadLen, wallSec)
	return goodputMbps, st, totalSent
}

// TestLocalizeConnectUDPH2ParallelSessionsInstant512 compares 1 vs 2 vs 4 independent H2 sessions @512B.
func TestLocalizeConnectUDPH2ParallelSessionsInstant512(t *testing.T) {
	const duration = connectUDPSynthProdBenchDuration
	link := tlsFlushTaxH2Link{Tax: 4 * time.Microsecond}
	for _, par := range []int{1, 2, 4} {
		mbps, st, sent := benchConnectUDPH2ParallelSessionsUpload(t, par, link, duration, connectudp.DefaultBenchUDPPayloadLen, 0)
		t.Logf("LOCALIZE h2 parallel-sessions=%d instant 512B: goodput=%.1f Mbit/s loss=%.2f%% rx=%d/%d",
			par, mbps, st.LossPct, st.RxPkts, sent)
	}
}

// TestLocalizeConnectUDPH2ShardedSingleSessionInstant512: one ListenPacket, 4 TCP pools via env.
func TestLocalizeConnectUDPH2ShardedSingleSessionInstant512(t *testing.T) {
	t.Setenv("MASQUE_H2_CONNECT_UDP_UPLOAD_STREAMS", "4")
	const duration = connectUDPSynthProdBenchDuration
	link := tlsFlushTaxH2Link{Tax: 4 * time.Microsecond}
	mbps, st, sent := benchConnectUDPH2ParallelSessionsUpload(t, 1, link, duration, connectudp.DefaultBenchUDPPayloadLen, 0)
	t.Logf("LOCALIZE h2 sharded single-session streams=4 instant: goodput=%.1f loss=%.2f%% rx=%d/%d",
		mbps, st.LossPct, st.RxPkts, sent)
	const wantMbps = 450.0
	if mbps < wantMbps {
		t.Fatalf("sharded single-session instant: %.1f < %.0f Mbit/s", mbps, wantMbps)
	}
}

// TestLocalizeConnectUDPH2Parallel4SessionsPaced500 probes docker-shaped 500 Mbit/s with 4 TCP pools.
func TestLocalizeConnectUDPH2Parallel4SessionsPaced500(t *testing.T) {
	const duration = connectUDPSynthProdBenchDuration
	link := tlsFlushTaxH2Link{Tax: 4 * time.Microsecond}
	mbps, st, sent := benchConnectUDPH2ParallelSessionsUpload(t, 4, link, duration, connectudp.DefaultBenchUDPPayloadLen, 500)
	t.Logf("LOCALIZE h2 parallel=4 paced 500 512B: goodput=%.1f Mbit/s loss=%.2f%% rx=%d/%d",
		mbps, st.LossPct, st.RxPkts, sent)
	if !st.BurstZeroLossOK(connectudp.DefaultBenchUDPPayloadLen, connectudp.DefaultBurstMinRxRatio) {
		t.Fatalf("parallel=4 paced 500: zero-loss gate fail loss=%.2f%% rx=%d/%d", st.LossPct, st.RxPkts, sent)
	}
	const wantMbps = 380.0
	if mbps < wantMbps {
		t.Fatalf("parallel=4 paced 500: %.1f Mbit/s < %.0f", mbps, wantMbps)
	}
}

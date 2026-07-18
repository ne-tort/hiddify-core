package masque

// F7.1 pre_server localize: at high paced rates, SOCKS ASSOCIATE can drop while WriteTo
// blocks on QUIC send. Assert c2s_write_ok ≈ sent and compare direct vs SOCKS.

import (
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	"github.com/sagernet/sing-box/transport/masque/connectudp/flowstats"
)

// InttestLocalizeConnectUDPH3Paced500DirectVsSocksWriteGap bisects ASSOCIATE vs MASQUE WriteTo.
func InttestLocalizeConnectUDPH3Paced500DirectVsSocksWriteGap(t *testing.T) {
	t.Helper()
	localizeConnectUDPH3PacedWriteGap(t, 500.0)
}

// InttestLocalizeConnectUDPH3Paced600DirectVsSocksWriteGap same at 600.
func InttestLocalizeConnectUDPH3Paced600DirectVsSocksWriteGap(t *testing.T) {
	t.Helper()
	localizeConnectUDPH3PacedWriteGap(t, 600.0)
}

func localizeConnectUDPH3PacedWriteGap(t *testing.T, target float64) {
	t.Helper()
	dur := connectUDPSynthProdBenchDuration
	flowstats.Enable()

	run := func(name string, socks bool) (got connectUDPPacedBenchResult, writeOK, writeFail uint64, qDelta uint64) {
		t.Helper()
		flowstats.Reset()
		beforeQ := http3.StreamDatagramQueueDropTotal()
		beforeRcv := quic.DatagramReceiveQueueDropTotal()
		got = benchConnectUDPPacedSinkGoodput(t, socks, dur, target)
		snap := flowstats.TakeSnapshot()
		writeOK, writeFail = snap.C2SWriteOK, snap.C2SWriteFail
		qDelta = http3.StreamDatagramQueueDropTotal() - beforeQ
		rcvDelta := quic.DatagramReceiveQueueDropTotal() - beforeRcv
		gap := int64(got.sentPkts) - int64(writeOK)
		t.Logf("RESULT_H3_WRITE_GAP target=%.0f via=%s goodput=%.2f loss=%.3f%% sent=%d write_ok=%d write_fail=%d gap=%d stream_q_drops=%d rcv_q_drops=%d",
			target, name, got.mbps, got.stats.LossPct, got.sentPkts, writeOK, writeFail, gap, qDelta, rcvDelta)
		return got, writeOK, writeFail, qDelta
	}

	direct, dOK, dFail, dQ := run("direct", false)
	socks, sOK, sFail, sQ := run("socks", true)

	assertConnectUDPProbeLoss(t, "h3 direct write-gap", direct.stats, 1.0)
	// After soft datagram backlog limit: SOCKS must not microburst into QUIC loss.
	// write_ok≈sent (ASSOCIATE holds); E2E loss ≈ direct (not ASSOCIATE-only gap).
	assertConnectUDPProbeLoss(t, "h3 socks write-gap", socks.stats, 2.0)
	if dFail != 0 || sFail != 0 {
		t.Fatalf("c2s_write_fail direct=%d socks=%d", dFail, sFail)
	}
	if dQ != 0 || sQ != 0 {
		t.Fatalf("stream_datagram_queue_drops delta direct=%d socks=%d", dQ, sQ)
	}
	assertWriteGap(t, "direct", direct.sentPkts, dOK, 0.01)
	assertWriteGap(t, "socks", socks.sentPkts, sOK, 0.02)

	// Soft backpressure may keep goodput under paced target (same as direct self-limit).
	minFloor := connectudp.MinPacedGoodputMbit(target) * 0.75
	if direct.mbps < minFloor {
		t.Fatalf("direct @%.0f goodput %.2f < floor %.2f", target, direct.mbps, minFloor)
	}
	if socks.mbps < minFloor {
		t.Fatalf("socks @%.0f goodput %.2f < floor %.2f", target, socks.mbps, minFloor)
	}
}

func assertWriteGap(t *testing.T, label string, sent int, writeOK uint64, maxFrac float64) {
	t.Helper()
	if sent <= 0 {
		t.Fatalf("%s sent=%d", label, sent)
	}
	if float64(writeOK) >= float64(sent)*0.99 {
		return
	}
	gap := float64(sent) - float64(writeOK)
	if gap < 0 {
		gap = -gap
	}
	if gap/float64(sent) > maxFrac {
		t.Fatalf("%s write gap: sent=%d write_ok=%d gap=%.0f (%.2f%% > %.2f%%) — ASSOCIATE/WriteTo drop before MASQUE",
			label, sent, writeOK, gap, 100*gap/float64(sent), 100*maxFrac)
	}
}

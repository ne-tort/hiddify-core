package probe_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
	"github.com/sagernet/sing-box/transport/masque/connectudp/probe"
)

func TestUDPProbeAnalyzeNoLoss(t *testing.T) {
	const (
		runID      = uint32(42)
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
		sent       = 100
	)
	sink := probe.NewSequencedSink(runID)
	for i := range sent {
		sink.Record(probe.BuildProbePayload(uint64(i), runID, payloadLen))
	}
	st := sink.Analyze(sent, payloadLen)
	if st.LossPkts != 0 || st.LossPct != 0 || st.ExcessPkts != 0 {
		t.Fatalf("loss=%d excess=%d (%.2f%%) want 0", st.LossPkts, st.ExcessPkts, st.LossPct)
	}
	if !st.BurstZeroLossOK(payloadLen, probe.DefaultBurstMinRxRatio) {
		t.Fatalf("BurstZeroLossOK false: %+v", st)
	}
	if !st.FillIntegrityOK(payloadLen) {
		t.Fatalf("fill hash mismatch: %s", st.FillSHA256)
	}
}

func TestUDPProbeAnalyzeExcess(t *testing.T) {
	const (
		runID      = uint32(9)
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	)
	sink := probe.NewSequencedSink(runID)
	for i := range 120 {
		sink.Record(probe.BuildProbePayload(uint64(i), runID, payloadLen))
	}
	st := sink.Analyze(100, payloadLen)
	if st.ExcessPkts != 20 {
		t.Fatalf("excess=%d want 20", st.ExcessPkts)
	}
	if st.BurstZeroLossOK(payloadLen, probe.DefaultBurstMinRxRatio) {
		t.Fatal("BurstZeroLossOK should fail when rx > sent")
	}
}

func TestSequencedSinkReset(t *testing.T) {
	const (
		runA       = uint32(1)
		runB       = uint32(2)
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	)
	sink := probe.NewSequencedSink(runA)
	for i := range 50 {
		sink.Record(probe.BuildProbePayload(uint64(i), runA, payloadLen))
	}
	sink.Reset(runB)
	for i := range 40 {
		sink.Record(probe.BuildProbePayload(uint64(i), runB, payloadLen))
	}
	st := sink.Analyze(40, payloadLen)
	if st.RxPkts != 40 || st.LossPct != 0 || st.DupPct != 0 {
		t.Fatalf("after reset: rx=%d loss=%.2f dup=%.2f", st.RxPkts, st.LossPct, st.DupPct)
	}
}

func TestUDPProbeAnalyzeLoss(t *testing.T) {
	const (
		runID      = uint32(7)
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	)
	sink := probe.NewSequencedSink(runID)
	for i := range 50 {
		sink.Record(probe.BuildProbePayload(uint64(i), runID, payloadLen))
	}
	st := sink.Analyze(100, payloadLen)
	if st.LossPkts != 50 {
		t.Fatalf("loss_pkts=%d want 50", st.LossPkts)
	}
	if st.LossPct != 50 {
		t.Fatalf("loss_pct=%.2f want 50", st.LossPct)
	}
}

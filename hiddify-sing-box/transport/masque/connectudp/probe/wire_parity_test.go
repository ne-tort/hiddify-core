package probe

import (
	"encoding/binary"
	"testing"
)

// GATE-UDP-SENDER: wire parity with docker/masque-perf-lab bench/udp_masque_send.py + udp_sink_analyze.py (UDP-5b2).

func TestGATEUDPProbeWireMatchesDockerSender(t *testing.T) {
	const (
		seq   = uint64(0x0123456789abcdef)
		runID = uint32(0xc0ffee01)
		plen  = 512
		sent  = 1000
	)
	p := BuildProbePayload(seq, runID, plen)
	if len(p) != plen {
		t.Fatalf("len=%d want %d", len(p), plen)
	}
	if got := binary.BigEndian.Uint64(p[0:8]); got != seq {
		t.Fatalf("seq=%#x want %#x", got, seq)
	}
	if got := binary.BigEndian.Uint32(p[8:12]); got != runID {
		t.Fatalf("run_id=%#x want %#x", got, runID)
	}
	for i := UDPProbeHeaderLen; i < len(p); i++ {
		if p[i] != 0 {
			t.Fatalf("fill byte@%d=%d want 0", i, p[i])
		}
	}

	sink := NewSequencedSink(runID)
	for i := range sent {
		sink.Record(BuildProbePayload(uint64(i), runID, plen))
	}
	st := sink.Analyze(sent, plen)
	if st.RxPkts != sent || st.LossPct != 0 || st.DupPct != 0 {
		t.Fatalf("sequenced analyze: %+v", st)
	}
	wantFill := UDPProbeFillSHA256(sent, plen)
	if st.FillSHA256 != wantFill {
		t.Fatalf("fill_sha256=%s want %s", st.FillSHA256, wantFill)
	}
	if !st.FillIntegrityOK(plen) || !st.BurstZeroLossOK(plen, DefaultBurstMinRxRatio) {
		t.Fatalf("integrity/zero-loss gate: %+v", st)
	}
}

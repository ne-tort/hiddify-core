package masque

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
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

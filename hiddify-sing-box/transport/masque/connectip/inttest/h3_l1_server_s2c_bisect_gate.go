//go:build masque_inttest_heavy

package inttest

// P6-H3-S2C-SERVER: onward direct vs H3 conn-wire S2C (+ relaystats).

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectip/relaystats"
)

const (
	h3S2CBisectBenchDur            = NativeSynthBenchDur
	h3S2CBisectMinBytes            = 4 * 1024 * 1024
	h3S2CBisectOnwardDirectMinMbps = 500.0
	h3S2CBisectConnOnwardMaxRatio  = 0.55
	h3S2CBisectH3DownFloor         = h3PerfDownFloor
	h3S2CBisectH3DownCeiling       = h3PerfDownCeiling
)

// RunGATEConnectIPH3L1ServerS2CBisect localizes onward vs H3 CONNECT-IP wire.
func RunGATEConnectIPH3L1ServerS2CBisect(t *testing.T) {
	t.Helper()
	onward := runOnwardDirectDownloadSample(t, h3S2CBisectBenchDur)

	relaystats.EnableForBench()
	relaystats.Reset()
	connStack := openConnectIPH3ConnWire(t)
	s2c := runConnWireUDPFountainWithS2CStats(t, connStack, "conn-wire-h3", h3S2CBisectBenchDur, connWireUDPFountainPayloadLen)
	srv := relaystats.SnapshotNow()

	logAndAnalyzeH3ServerS2CBisect(t, onward, s2c, srv)
}

func logAndAnalyzeH3ServerS2CBisect(t *testing.T, onward ThroughputSample, s2c connWireS2CResult, srv relaystats.Snapshot) {
	t.Helper()
	client := s2c.Client
	t.Logf("S2C-H3 onward %s", onward)
	t.Logf("S2C-H3 client %s", client)
	t.Logf("S2C-H3 relaystats c2s_plane_in=%d s2c_out=%d s2c_write_fail=%d s2c_rto=%d download_q_high=%d",
		srv.C2SPlaneIn, srv.S2COut, srv.S2CWriteFail, srv.S2CRTORetransmit, srv.DownloadQHigh)

	if onward.Bytes < h3S2CBisectMinBytes {
		t.Fatalf("onward direct bytes=%d want>=%d", onward.Bytes, h3S2CBisectMinBytes)
	}
	if onward.Mbps < h3S2CBisectOnwardDirectMinMbps {
		t.Fatalf("onward direct %.1f < %.0f — harness broken", onward.Mbps, h3S2CBisectOnwardDirectMinMbps)
	}
	if client.Bytes < h3S2CBisectMinBytes {
		t.Fatalf("conn-wire client bytes=%d want>=%d", client.Bytes, h3S2CBisectMinBytes)
	}
	if client.Mbps < h3S2CBisectH3DownFloor || client.Mbps > h3S2CBisectH3DownCeiling {
		t.Fatalf("conn-wire H3 %.1f outside band [%.0f, %.0f]", client.Mbps, h3S2CBisectH3DownFloor, h3S2CBisectH3DownCeiling)
	}

	connOnwardRatio := client.Mbps / onward.Mbps
	t.Logf("S2C-H3 conn-wire/onward-direct ratio=%.2f (wire=%.1f onward=%.1f)",
		connOnwardRatio, client.Mbps, onward.Mbps)
	if connOnwardRatio > h3S2CBisectConnOnwardMaxRatio {
		t.Fatalf("conn-wire/onward %.2f > %.2f — expected connect-ip+H3 tax",
			connOnwardRatio, h3S2CBisectConnOnwardMaxRatio)
	}
	t.Logf("S2C-H3 PASS: onward >> conn-wire (ratio=%.2f); wire=%.0f in H3 band",
		connOnwardRatio, client.Mbps)
}

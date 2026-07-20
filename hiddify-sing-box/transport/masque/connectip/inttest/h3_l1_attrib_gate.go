//go:build masque_inttest_heavy

package inttest

// P6-H3-ATTRIB: decompose real L1 H3 download into client prefetch/write vs wall byte-tax.

import (
	"bytes"
	"runtime/pprof"
	"testing"
	"time"

	connectipgo "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/transport/masque/connectip/relaystats"
)

const (
	h3AttribBenchDur     = NativeSynthBenchDur
	h3AttribMinBytes     = 4 * 1024 * 1024
	h3AttribTCPBandFloor = h3PerfDownFloor
	h3AttribTCPBandCeil  = h3PerfDownCeiling
)

type h3AttribSnapshot struct {
	TCP           ThroughputSample
	WriteOK       uint64
	WriteFail     uint64
	WriteBytes    uint64
	Flush         uint64
	IngressDrops  uint64
	H3PrefetchIn  uint64
	H3PrefetchOut uint64
	S2CPlaneOut   uint64
	S2CRTO        uint64
	S2CWriteFail  uint64
}

func snapshotH3Attrib(tb testing.TB, stack *connectIPL1Stack, dur time.Duration) h3AttribSnapshot {
	tb.Helper()
	connectipgo.EnableCIPClientRelayStats()
	connectipgo.ResetCIPClientRelayStats()
	connectipgo.ResetStreamCapsuleDatagramIngressDropTotal()
	relaystats.EnableForBench()
	relaystats.Reset()

	tcp := runL1DownloadSample(tb, stack, "l1-h3", dur)
	cli := connectipgo.SnapshotCIPClientRelayStats()
	srv := relaystats.SnapshotNow()
	return h3AttribSnapshot{
		TCP:           tcp,
		WriteOK:       cli.WriteOK,
		WriteFail:     cli.WriteFail,
		WriteBytes:    cli.WriteBytes,
		Flush:         cli.Flush,
		IngressDrops:  cli.IngressDrops,
		H3PrefetchIn:  cli.H3PrefetchIn,
		H3PrefetchOut: cli.H3PrefetchOut,
		S2CPlaneOut:   srv.S2COut,
		S2CRTO:        srv.S2CRTORetransmit,
		S2CWriteFail:  srv.S2CWriteFail,
	}
}

// RunGATEConnectIPH3L1Attrib attributes H3 L1 download with client + server counters + optional pprof.
func RunGATEConnectIPH3L1Attrib(t *testing.T) {
	t.Helper()
	stack := openConnectIPH3L1Pipe(t)

	var cpuBuf bytes.Buffer
	if err := pprof.StartCPUProfile(&cpuBuf); err != nil {
		t.Fatalf("StartCPUProfile: %v", err)
	}
	snap := snapshotH3Attrib(t, stack, h3AttribBenchDur)
	pprof.StopCPUProfile()

	logAndAnalyzeH3Attrib(t, snap)
	if cpuBuf.Len() > 0 {
		logTopCPUFunctions(t, cpuBuf.Bytes(), 12)
	}
}

func logAndAnalyzeH3Attrib(t *testing.T, s h3AttribSnapshot) {
	t.Helper()
	if s.TCP.Bytes < h3AttribMinBytes {
		t.Fatalf("attrib bytes=%d want>=%d", s.TCP.Bytes, h3AttribMinBytes)
	}
	if s.TCP.Mbps < h3AttribTCPBandFloor || s.TCP.Mbps > h3AttribTCPBandCeil {
		t.Fatalf("attrib TCP %.1f outside band [%.0f, %.0f]", s.TCP.Mbps, h3AttribTCPBandFloor, h3AttribTCPBandCeil)
	}
	t.Logf("ATTRIB-H3 tcp %s", s.TCP)
	t.Logf("ATTRIB-H3 client write_ok=%d write_fail=%d write_bytes=%d flush=%d ingress_drops=%d",
		s.WriteOK, s.WriteFail, s.WriteBytes, s.Flush, s.IngressDrops)
	t.Logf("ATTRIB-H3 client h3_prefetch_in=%d h3_prefetch_out=%d", s.H3PrefetchIn, s.H3PrefetchOut)
	t.Logf("ATTRIB-H3 server s2c_out=%d s2c_write_fail=%d s2c_rto=%d",
		s.S2CPlaneOut, s.S2CWriteFail, s.S2CRTO)
	if s.IngressDrops > 0 {
		t.Fatalf("ingress_drops=%d during steady H3 attrib", s.IngressDrops)
	}
	if s.WriteFail > 0 {
		t.Logf("OPEN: client write_fail=%d during H3 download attrib", s.WriteFail)
	}
	if s.S2CRTO > 0 {
		t.Logf("OPEN: server S2C RTO retransmits=%d on local L1 (unexpected)", s.S2CRTO)
	}
	t.Logf("ATTRIB-H3 PASS: real L1 H3 attributed (tcp=%.1f Mbit/s ns/B=%.1f)", s.TCP.Mbps, s.TCP.NsPerByte)
}

//go:build masque_inttest_heavy

package inttest

// P6-D1-H2-ATTRIB: decompose real L1 H2 byte-tax into client ingress vs server S2C.

import (
	"bytes"
	"runtime/pprof"
	"sort"
	"testing"
	"time"

	connectipgo "github.com/quic-go/connect-ip-go"
	"github.com/google/pprof/profile"
)

const (
	h2AttribBenchDur       = NativeSynthBenchDur
	h2AttribMinBytes       = 4 * 1024 * 1024
	h2AttribTCPBandFloor   = h2PerfDownFloor
	h2AttribTCPBandCeiling = h2PerfDownCeiling
	h2AttribMaxCloneShare  = 0.05  // after REPLACE clone should be negligible
)

type h2AttribSnapshot struct {
	TCP              ThroughputSample
	ServerDatagrams  uint64
	ServerFlushes    uint64
	ServerFlushNs    uint64
	CapsuleParseNs   uint64
	IngressCloneNs   uint64
	IngressCloneB    uint64
	IngressEnqueued  uint64
	IngressEnqueuedB uint64
	ReadPacketNs     uint64
	ReadPacketCount  uint64
	IngressDrops     uint64
}

func snapshotH2Attrib(tb testing.TB, stack *connectIPL1Stack, layer string, dur time.Duration) h2AttribSnapshot {
	tb.Helper()
	connectipgo.ResetH2S2CStats()
	connectipgo.ResetH2ClientIngressAttrib()
	connectipgo.ResetStreamCapsuleDatagramIngressDropTotal()

	tcp := runL1DownloadSample(tb, stack, layer, dur)
	return h2AttribSnapshot{
		TCP:              tcp,
		ServerDatagrams:  connectipgo.H2S2CDatagramSentTotal(),
		ServerFlushes:    connectipgo.H2S2CFlushTotal(),
		ServerFlushNs:    connectipgo.H2S2CFlushNsTotal(),
		CapsuleParseNs:   connectipgo.H2ClientCapsuleReadParseNs(),
		IngressCloneNs:   connectipgo.H2ClientIngressCloneNs(),
		IngressCloneB:    connectipgo.H2ClientIngressCloneBytes(),
		IngressEnqueued:  connectipgo.H2ClientIngressEnqueued(),
		IngressEnqueuedB: connectipgo.H2ClientIngressEnqueuedBytes(),
		ReadPacketNs:     connectipgo.H2ClientReadPacketDeliverNs(),
		ReadPacketCount:  connectipgo.H2ClientReadPacketDelivered(),
		IngressDrops:     connectipgo.StreamCapsuleDatagramIngressDropTotal(),
	}
}

// RunGATEConnectIPH2L1Attrib decomposes real-stack byte-tax and optionally captures CPU profile.
func RunGATEConnectIPH2L1Attrib(t *testing.T) {
	t.Helper()
	stack := openConnectIPH2L1Pipe(t)

	var cpuBuf bytes.Buffer
	if err := pprof.StartCPUProfile(&cpuBuf); err != nil {
		t.Fatalf("StartCPUProfile: %v", err)
	}
	snap := snapshotH2Attrib(t, stack, "l1-tcp", h2AttribBenchDur)
	pprof.StopCPUProfile()

	logAndAnalyzeH2Attrib(t, snap)

	if cpuBuf.Len() > 0 {
		logTopCPUFunctions(t, cpuBuf.Bytes(), 12)
	}
}

func logAndAnalyzeH2Attrib(t *testing.T, s h2AttribSnapshot) {
	t.Helper()
	wallNs := s.TCP.Wall.Nanoseconds()
	if wallNs <= 0 {
		t.Fatal("attrib wall=0")
	}
	if s.TCP.Bytes < h2AttribMinBytes {
		t.Fatalf("attrib bytes=%d want>=%d", s.TCP.Bytes, h2AttribMinBytes)
	}
	if s.TCP.Mbps < h2AttribTCPBandFloor || s.TCP.Mbps > h2AttribTCPBandCeiling {
		t.Fatalf("attrib TCP %.1f outside band [%.0f, %.0f]", s.TCP.Mbps, h2AttribTCPBandFloor, h2AttribTCPBandCeiling)
	}

	totalClientNs := s.CapsuleParseNs + s.IngressCloneNs + s.ReadPacketNs
	cloneShare := 0.0
	parseShare := 0.0
	readShare := 0.0
	serverFlushShare := 0.0
	if totalClientNs > 0 {
		cloneShare = float64(s.IngressCloneNs) / float64(totalClientNs)
		parseShare = float64(s.CapsuleParseNs) / float64(totalClientNs)
		readShare = float64(s.ReadPacketNs) / float64(totalClientNs)
	}
	if wallNs > 0 {
		serverFlushShare = float64(s.ServerFlushNs) / float64(wallNs)
	}

	t.Logf("ATTRIB tcp %s", s.TCP)
	t.Logf("ATTRIB server S2C: datagrams=%d flushes=%d flush_ns=%d flush_share=%.1f%%",
		s.ServerDatagrams, s.ServerFlushes, s.ServerFlushNs, serverFlushShare*100)
	t.Logf("ATTRIB client ingress: parse_ns=%d clone_ns=%d clone_bytes=%d enqueued=%d enqueued_bytes=%d",
		s.CapsuleParseNs, s.IngressCloneNs, s.IngressCloneB, s.IngressEnqueued, s.IngressEnqueuedB)
	t.Logf("ATTRIB client ReadPacket: deliver_ns=%d count=%d", s.ReadPacketNs, s.ReadPacketCount)
	t.Logf("ATTRIB client shares (of tracked client ns): parse=%.1f%% clone=%.1f%% readpacket=%.1f%%",
		parseShare*100, cloneShare*100, readShare*100)
	t.Logf("ATTRIB ingress_drops=%d", s.IngressDrops)

	if s.IngressDrops > 0 {
		t.Fatalf("ingress_drops=%d during steady attrib bench", s.IngressDrops)
	}

	// After clone REPLACE, redundant copy should not dominate.
	if cloneShare > h2AttribMaxCloneShare && s.IngressCloneNs > 0 {
		t.Logf("ATTRIB OPEN: clone still %.1f%% of tracked client ns — further REPLACE candidates",
			cloneShare*100)
	}

	// Primary locus naming for RESULTS handoff.
	primary := "mixed"
	switch {
	case parseShare >= readShare && parseShare >= cloneShare:
		primary = "capsule_read_parse"
	case readShare >= parseShare && readShare >= cloneShare:
		primary = "readpacket_deliver"
	case cloneShare > h2AttribMaxCloneShare:
		primary = "ingress_clone"
	}
	t.Logf("ATTRIB primary_client_locus=%s byte_tax_ns/B=%.1f", primary, s.TCP.NsPerByte)
	t.Logf("ATTRIB PASS: real L1 attributed (tcp=%.1f Mbit/s ns/B=%.1f)", s.TCP.Mbps, s.TCP.NsPerByte)
}

func logTopCPUFunctions(t *testing.T, profileData []byte, topN int) {
	t.Helper()
	p, err := profile.Parse(bytes.NewReader(profileData))
	if err != nil {
		t.Logf("ATTRIB pprof parse: %v", err)
		return
	}
	if len(p.Sample) == 0 {
		return
	}
	total := int64(0)
	for _, s := range p.Sample {
		if len(s.Value) > 0 {
			total += s.Value[0]
		}
	}
	if total <= 0 {
		return
	}
	type flatEntry struct {
		name string
		flat int64
	}
	flatMap := make(map[string]int64)
	for _, s := range p.Sample {
		if len(s.Value) == 0 {
			continue
		}
		for _, loc := range s.Location {
			for _, line := range loc.Line {
				if line.Function == nil {
					continue
				}
				flatMap[line.Function.Name] += s.Value[0]
			}
		}
	}
	flats := make([]flatEntry, 0, len(flatMap))
	for name, flat := range flatMap {
		flats = append(flats, flatEntry{name: name, flat: flat})
	}
	sort.Slice(flats, func(i, j int) bool { return flats[i].flat > flats[j].flat })
	if topN > len(flats) {
		topN = len(flats)
	}
	t.Logf("ATTRIB pprof top CPU samples=%d:", len(p.Sample))
	for i := 0; i < topN; i++ {
		t.Logf("  %.1f%% %s", float64(flats[i].flat)/float64(total)*100, flats[i].name)
	}
}

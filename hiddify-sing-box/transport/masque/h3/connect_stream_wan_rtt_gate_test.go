//go:build masque_wan_rtt_synth

package h3

import (
	"sync/atomic"
	"testing"
	"time"

	sched "github.com/sagernet/sing-box/transport/masque/stream/sched"
)

// TestGATEH3SynthWindowedDownloadRTTSweep (H4): prod 256 KiB batch ceiling falls with WAN RTT.
func TestGATEH3SynthWindowedDownloadRTTSweep(t *testing.T) {
	type point struct {
		rtt    time.Duration
		minMbps float64
		maxMbps float64
	}
	points := []point{
		{rtt: 35 * time.Millisecond, minMbps: 40, maxMbps: 70},
		{rtt: 80 * time.Millisecond, minMbps: 18, maxMbps: 32},
		{rtt: 120 * time.Millisecond, minMbps: 12, maxMbps: 22},
	}
	var base float64
	for i, pt := range points {
		batch := sched.DownloadDeliveryWakeBatch(pt.rtt)
		mbps := benchWindowedBidiLinkRTT(pt.rtt, TunnelWriteToBufLen)
		// Windowed bench is S2C-window limited; wake batch is logged for policy regression.
		ceil := sched.TheoreticalDownloadCeilingMbps(TunnelWriteToBufLen, pt.rtt)
		t.Logf("RTT=%s throughput=%.1f Mbit/s theoretical=%.1f wake_batch=%d", pt.rtt, mbps, ceil, batch)
		if mbps < pt.minMbps || mbps > pt.maxMbps {
			t.Fatalf("RTT=%s throughput=%.1f want %.0f–%.0f", pt.rtt, mbps, pt.minMbps, pt.maxMbps)
		}
		ratio := mbps / ceil
		if ratio < 0.55 || ratio > 1.45 {
			t.Fatalf("RTT=%s peak/theoretical=%.2f want 0.55–1.45", pt.rtt, ratio)
		}
		if i == 0 {
			base = mbps
			if batch != sched.DownloadDeliveryWakeBDPBytes {
				t.Fatalf("RTT=%s wake_batch=%d want %d", pt.rtt, batch, sched.DownloadDeliveryWakeBDPBytes)
			}
			continue
		}
		baseRTT := points[0].rtt.Seconds()
		wantScale := baseRTT / pt.rtt.Seconds()
		gotScale := mbps / base
		if gotScale < wantScale*0.55 || gotScale > wantScale*1.45 {
			t.Fatalf("RTT=%s scale=%.2f want ~%.2f (batch/RTT model)", pt.rtt, gotScale, wantScale)
		}
	}
}

// TestGATEH3SynthWindowedDownloadMin50 @35ms RTT: windowed prod download ≥50 Mbit/s.
func TestGATEH3SynthWindowedDownloadMin50(t *testing.T) {
	const minMbps = 50.0
	mbps := benchWindowedProdTunnelConnMbps(35*time.Millisecond, TunnelWriteToBufLen)
	t.Logf("prod TunnelConn windowed @35ms: %.1f Mbit/s", mbps)
	if mbps < minMbps {
		t.Fatalf("download %.1f Mbit/s want >= %.0f", mbps, minMbps)
	}
}

// TestGATEH3SynthWindowedDownloadRTT80 @80ms: proportional floor ≥25 Mbit/s.
func TestGATEH3SynthWindowedDownloadRTT80(t *testing.T) {
	const minMbps = 25.0
	mbps := benchWindowedProdTunnelConnMbps(80*time.Millisecond, TunnelWriteToBufLen)
	t.Logf("prod TunnelConn windowed @80ms: %.1f Mbit/s", mbps)
	if mbps < minMbps {
		t.Fatalf("download %.1f Mbit/s want >= %.0f", mbps, minMbps)
	}
}

type testDownloadWakeSink struct {
	upload int32
	down   int32
}

func (s *testDownloadWakeSink) NoteUploadWake()   { atomic.AddInt32(&s.upload, 1) }
func (s *testDownloadWakeSink) NoteDownloadWake() { atomic.AddInt32(&s.down, 1) }

// TestGATEConnectStreamWriteToUsesMS3Reader ensures prod WriteTo uses readH3Download (per-chunk MS3 wakes).
func TestGATEConnectStreamWriteToUsesMS3Reader(t *testing.T) {
	sink := &testDownloadWakeSink{}
	stream := newRefBenchInfiniteStream()
	conn := NewTunnelConn(TunnelConnParams{H3Stream: stream, BidiWakeSink: sink})
	conn.beginDuplexDownload()
	defer conn.endDuplexDownload()
	benchSink := newBenchWindowedSink(35*time.Millisecond, TunnelWriteToBufLen, benchWindowedDuration)
	n, _ := conn.WriteTo(benchSink)
	if n < 1<<20 {
		t.Fatalf("short download %d want >=1MiB", n)
	}
	wakes := atomic.LoadInt32(&sink.down)
	if wakes < 8 {
		t.Fatalf("download wakes=%d want >=8 (MS3 per-chunk; not single http3.WriteTo wake)", wakes)
	}
}

// TestGATEH3HTTP3WriteToWakeBatchMatchesSched (PR-B): default wake batch follows sched, not legacy 256 KiB.
func TestGATEH3HTTP3WriteToWakeBatchMatchesSched(t *testing.T) {
	const legacy = 256 * 1024
	batch := sched.DownloadDeliveryWakeBatch(0)
	if batch == legacy {
		t.Fatalf("zero RTT batch=%d must not equal legacy http3 default %d", batch, legacy)
	}
	if batch != sched.DownloadDeliveryWakeBDPBytes {
		t.Fatalf("zero RTT batch=%d want %d", batch, sched.DownloadDeliveryWakeBDPBytes)
	}
	SetTestConnectStreamPeerRTT(100 * time.Millisecond)
	defer ClearTestConnectStreamPeerRTT()
	at100 := ProdConnectStreamSchedPolicy().DownloadDeliveryWakeBatch(100 * time.Millisecond)
	if at100 <= sched.DownloadDeliveryWakeBDPBytes {
		t.Fatalf("100ms batch=%d want > %d", at100, sched.DownloadDeliveryWakeBDPBytes)
	}
}

// TestGATEConnectStreamSchedColdStartWake wakes on the first delivery byte.
func TestGATEConnectStreamSchedColdStartWake(t *testing.T) {
	sink := &testDownloadWakeSink{}
	stream := newRefBenchInfiniteStream()
	conn := NewTunnelConn(TunnelConnParams{H3Stream: stream, BidiWakeSink: sink})
	conn.beginDuplexDownload()
	defer conn.endDuplexDownload()
	sched := conn.scheduler
	sched.noteDownloadDelivery(4096)
	if got := atomic.LoadInt32(&sink.down); got < 1 {
		t.Fatalf("cold-start download wakes=%d want >=1", got)
	}
	before := atomic.LoadInt32(&sink.down)
	sched.noteDownloadDelivery(4096)
	if got := atomic.LoadInt32(&sink.down); got <= before {
		t.Fatalf("download-primary delivery wake: before=%d after=%d", before, got)
	}
}

// TestGATEConnectStreamSchedRTTWakeBatch scales batch with injected RTT.
func TestGATEConnectStreamSchedRTTWakeBatch(t *testing.T) {
	p := ProdConnectStreamSchedPolicy()
	if got := p.DownloadDeliveryWakeBatch(0); got != sched.DownloadDeliveryWakeBDPBytes {
		t.Fatalf("zero RTT batch=%d want %d", got, sched.DownloadDeliveryWakeBDPBytes)
	}
	SetTestConnectStreamPeerRTT(100 * time.Millisecond)
	defer ClearTestConnectStreamPeerRTT()
	want := p.DownloadDeliveryWakeBatch(100 * time.Millisecond)
	if want <= sched.DownloadDeliveryWakeBDPBytes {
		t.Fatalf("100ms batch=%d want > %d", want, sched.DownloadDeliveryWakeBDPBytes)
	}
	if want > sched.DownloadDeliveryWakeMaxBytes {
		t.Fatalf("100ms batch=%d exceeds cap %d", want, sched.DownloadDeliveryWakeMaxBytes)
	}
}

// TestGATEDownloadPrimaryTLSAckDoesNotArmDuplex: sub-4KiB upload during bulk download stays download-primary.
func TestGATEDownloadPrimaryTLSAckDoesNotArmDuplex(t *testing.T) {
	conn := NewTunnelConn(TunnelConnParams{H3Stream: newRefBenchInfiniteStream(), RouteBidiDuplex: true})
	conn.beginDuplexDownload()
	defer conn.endDuplexDownload()
	ack := make([]byte, 8*1024)
	if _, err := conn.Write(ack); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&conn.duplexUploadStarted) != 0 {
		t.Fatal("TLS-ACK-sized upload armed saturated duplex")
	}
}

// TestGATESaturatedDuplexNotArmedOnProdHotPath: bulk upload during download stays download-primary (h2o thin).
func TestGATESaturatedDuplexNotArmedOnProdHotPath(t *testing.T) {
	conn := NewTunnelConn(TunnelConnParams{H3Stream: newRefBenchInfiniteStream(), RouteBidiDuplex: true})
	conn.beginDuplexDownload()
	defer conn.endDuplexDownload()
	for _, n := range []int{64 * 1024, 64 * 1024, 64 * 1024, 64 * 1024} {
		if _, err := conn.Write(make([]byte, n)); err != nil {
			t.Fatal(err)
		}
	}
	if atomic.LoadInt32(&conn.duplexUploadStarted) != 0 {
		t.Fatal("prod hot path must not arm saturated duplex overlay")
	}
}

func TestGATEDownloadPrimaryTLSAckChunksDoNotArmDuplex(t *testing.T) {
	conn := NewTunnelConn(TunnelConnParams{H3Stream: newRefBenchInfiniteStream(), RouteBidiDuplex: true})
	conn.beginDuplexDownload()
	defer conn.endDuplexDownload()
	for i := 0; i < 40; i++ {
		if _, err := conn.Write(make([]byte, 512)); err != nil {
			t.Fatal(err)
		}
	}
	if atomic.LoadInt32(&conn.duplexUploadStarted) != 0 {
		t.Fatal("TLS-ACK-sized chunks must not arm saturated duplex")
	}
}

// TestGATEH3WindowedBidiLinkBaseline @35ms baseline for regression manifest.
func TestGATEH3WindowedBidiLinkBaseline(t *testing.T) {
	mbps := benchWindowedBidiLink()
	if mbps < 21.0 {
		t.Fatalf("benchWindowedBidiLink=%.1f want >=21", mbps)
	}
}

// TestGATEH3SynthThinVsProdWindowed (FIX-THIN A/B): thin client vs prod MS3 @35ms windowed mock.
func TestGATEH3SynthThinVsProdWindowed(t *testing.T) {
	const rtt = 35 * time.Millisecond
	prod := benchWindowedProdTunnelConnMbps(rtt, TunnelWriteToBufLen)
	thin := benchWindowedThinTunnelConnMbps(rtt, TunnelWriteToBufLen)
	ratio := thin / prod
	t.Logf("FIX-THIN A/B @35ms: prod=%.1f Mbit/s thin=%.1f Mbit/s ratio=%.2f", prod, thin, ratio)
	if prod < 50.0 {
		t.Fatalf("prod %.1f Mbit/s want >=50 (regression)", prod)
	}
	if thin < 50.0 {
		t.Fatalf("thin %.1f Mbit/s want >=50", thin)
	}
	if ratio < 0.85 {
		t.Fatalf("thin/prod=%.2f want >=0.85 (thin should not regress vs prod on mock)", ratio)
	}
}

package connectip

import (
	"io"
	"testing"
	"time"
)

func TestSyntheticH2WritePacketBenchSmoke(t *testing.T) {
	r := SyntheticH2WritePacketBench(H2C2SNoWakeVis, 1200, 200*time.Millisecond, io.Discard)
	if r.Bytes <= 0 || r.Mbps < 50 {
		t.Fatalf("vis discard too low: %+v", r)
	}
	if r.PipeWrites == 0 || r.WriteOK == 0 {
		t.Fatalf("missing counters: %+v", r)
	}
	ratio := float64(r.WriteOK) / float64(r.PipeWrites)
	// Default LoopBatch=16 < VisMax=32 → flush-bound ratio ≈16; still ≫ wake 1:1.
	if ratio < 2.0 {
		t.Fatalf("vis coalesce pipe ratio=%.2f want >=2; %+v", ratio, r)
	}
	t.Logf("NoWakeVis discard: %.0f Mbit/s write_ok=%d pipe=%d ratio=%.2f (prod N=%d)", r.Mbps, r.WriteOK, r.PipeWrites, ratio, H2C2SVisMaxPkts())
}

// TestGATEH2C2SAsymLocalize reproduces docker-class UP underlay tax in-proc:
// paced per-Write underlay → wake 1:1 ≪ NoWake vis; vis raises Mbps and cuts pipe Writes.
func TestGATEH2C2SAsymLocalize(t *testing.T) {
	const (
		ipLen = 1200
		dur   = 400 * time.Millisecond
		// ~25µs/Write ≈ H2 framing class; coalescing 4:1 should approach ~4× Mbps.
		drain = 25 * time.Microsecond
	)
	wake, vis, ratio := SyntheticH2C2SAsymLocalize(ipLen, dur, drain)
	t.Logf("wake: %.1f Mbit/s pipe=%d write_ok=%d", wake.Mbps, wake.PipeWrites, wake.WriteOK)
	t.Logf("vis:  %.1f Mbit/s pipe=%d write_ok=%d ratio=%.2f", vis.Mbps, vis.PipeWrites, vis.WriteOK, ratio)

	if wake.Mbps <= 0 || vis.Mbps <= 0 {
		t.Fatalf("zero Mbps wake=%v vis=%v", wake, vis)
	}
	if vis.Mbps < wake.Mbps*2.0 {
		t.Fatalf("vis %.1f not ≥2× wake %.1f — coalesce not cutting paced underlay tax", vis.Mbps, wake.Mbps)
	}
	if ratio < 2.5 || ratio > 8.0 {
		t.Fatalf("vis pipe ratio=%.2f want ~4 (N=%d)", ratio, H2C2SVisMaxPkts())
	}
	_, s2cMbps := SyntheticH2ReadPacketBench(ipLen, dur)
	t.Logf("s2c read synth: %.1f Mbit/s; wake/s2c=%.2f vis/s2c=%.2f", s2cMbps, wake.Mbps/s2cMbps, vis.Mbps/s2cMbps)
	// Class lock: paced C2S wake stays well below in-mem S2C (UP≪DOWN shape).
	if wake.Mbps > s2cMbps*0.5 {
		t.Fatalf("wake C2S %.1f not ≪ s2c %.1f — paced tax too weak for asym class", wake.Mbps, s2cMbps)
	}
}

func TestGATEH2C2SInPlaceNoRetainCopy(t *testing.T) {
	// Contract: SendProxiedIPDatagramNoWake must not retain ipPacket after return,
	// so Conn.WritePacketInPlaceNoWake must not allocate a defensive copy for H2.
	EnableCIPClientRelayStats()
	ResetCIPClientRelayStats()
	capW := &countingPipeWriter{}
	bodyR, bodyW := io.Pipe()
	str := &h2CapsulePipeStream{body: bodyR, pipeW: capW}
	conn := newProxiedConn(str, true)
	defer conn.Close()
	defer bodyR.Close()
	defer bodyW.Close()

	ip := make([]byte, 40)
	ip[0] = 0x45
	ip[2], ip[3] = 0, 40
	ip[8] = 64
	ip[9] = 6
	ip[12], ip[16] = 1, 2

	icmp, retained, err := conn.WritePacketInPlaceNoWake(ip)
	if err != nil {
		t.Fatal(err)
	}
	if retained {
		t.Fatal("H2 coalesced path must not retain pool buffer")
	}
	if icmp != nil {
		t.Fatalf("unexpected icmp")
	}
	if ip[8] != 63 {
		t.Fatalf("TTL want 63 got %d", ip[8])
	}
	// Mutate caller buffer after return — pendingVis must already own a copy.
	ip[9] = 0xFF
	conn.FlushOutgoingDatagramSend()
	if capW.writes != 1 {
		t.Fatalf("writes=%d want 1", capW.writes)
	}
	// Capsule payload = ctxID||IP; proto at ctxLen+9 must still be 6.
	raw := capW.buf.Bytes()
	if len(raw) < len(contextIDZero)+20 {
		t.Fatalf("wire too short: %d", len(raw))
	}
	// Skip capsule type+len varints: parse loosely by searching for TTL=63 + proto.
	found := false
	for i := 0; i+10 < len(raw); i++ {
		if raw[i+8] == 63 && raw[i+9] == 6 && raw[i] == 0x45 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("wire missing prepared IPv4 (proto=6); caller mutate leaked? len=%d", len(raw))
	}
}

// TestGATEH2C2SVisNCurve: under paced Write, Mbps scales with VisMaxPkts (pipe Writes⁻¹).
func TestGATEH2C2SVisNCurve(t *testing.T) {
	const (
		ipLen = 1200
		dur   = 300 * time.Millisecond
		drain = 25 * time.Microsecond
	)
	ns := []int{1, 2, 4, 8, 16, 32}
	rows := SyntheticH2C2SVisNCurve(ipLen, dur, drain, ns)
	if len(rows) != len(ns) {
		t.Fatalf("rows=%d want %d", len(rows), len(ns))
	}
	var prev float64
	for i, r := range rows {
		n := ns[i]
		ratio := 0.0
		if r.PipeWrites > 0 {
			ratio = float64(r.WriteOK) / float64(r.PipeWrites)
		}
		t.Logf("N=%2d: %.1f Mbit/s write_ok=%d pipe=%d ratio=%.2f", n, r.Mbps, r.WriteOK, r.PipeWrites, ratio)
		if r.Mbps <= 0 {
			t.Fatalf("N=%d zero Mbps", n)
		}
		// ratio ≈ N (flush tails soften slightly)
		if ratio < float64(n)*0.6 || ratio > float64(n)*1.3 {
			t.Fatalf("N=%d pipe ratio=%.2f want ~%d", n, ratio, n)
		}
		if i > 0 && r.Mbps < prev*1.2 {
			t.Fatalf("N=%d mbps %.1f not ≥1.2× prior N=%d %.1f — underlay not Write-bound", n, r.Mbps, ns[i-1], prev)
		}
		prev = r.Mbps
	}
}

// TestGATEH2RelayPolicyAsymExplain: C2S N is intentionally below relay S2C N=32
// (docker: N=32 → Fountain-class UP death). Gate locks the safe band and documents the gap.
func TestGATEH2RelayPolicyAsymExplain(t *testing.T) {
	const (
		ipLen = 1200
		dur   = 350 * time.Millisecond
		drain = 25 * time.Microsecond
	)
	c2sN := H2C2SVisMaxPkts()
	relayN := H2RelayS2CBatchMaxPkts()
	if c2sN != 16 {
		t.Fatalf("C2S vis N=%d want 16 (docker KEEP post ACK Flush: 16→~1140/1290; 24→~1060)", c2sN)
	}
	if relayN != 32 {
		t.Fatalf("relay S2C batch N=%d want 32", relayN)
	}

	w1 := newPacedUnderlayWriter(drain)
	c2s := SyntheticH2WritePacketBenchOpts(H2C2SWriteBenchOpts{
		Mode: H2C2SNoWakeVis, IPPacketLen: ipLen, Dur: dur, Dst: w1,
		VisMaxPkts: c2sN, VisMaxBytes: 1 << 20, LoopBatch: 64,
	})
	w1.Close()

	w2 := newPacedUnderlayWriter(drain)
	relayClass := SyntheticH2WritePacketBenchOpts(H2C2SWriteBenchOpts{
		Mode: H2C2SNoWakeVis, IPPacketLen: ipLen, Dur: dur, Dst: w2,
		VisMaxPkts: relayN, VisMaxBytes: 1 << 20, LoopBatch: 128,
	})
	w2.Close()

	gain := relayClass.Mbps / c2s.Mbps
	t.Logf("C2S N=%d:  %.1f Mbit/s pipe=%d", c2sN, c2s.Mbps, c2s.PipeWrites)
	t.Logf("relay N=%d: %.1f Mbit/s pipe=%d (synth only — docker cannot use N=32 on C2S)", relayN, relayClass.Mbps, relayClass.PipeWrites)
	t.Logf("relay/C2S synth gain=%.2f (headroom if TCP clock were free)", gain)

	if c2s.Mbps < float64(c2sN)*15 {
		t.Fatalf("C2S N=%d only %.1f Mbit/s under paced Write", c2sN, c2s.Mbps)
	}
	if gain < 1.5 {
		t.Fatalf("expected relay-class synth ≫ C2S N=%d; gain=%.2f", c2sN, gain)
	}
}


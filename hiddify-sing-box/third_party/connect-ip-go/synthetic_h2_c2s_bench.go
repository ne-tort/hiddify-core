package connectip

import (
	"io"
	"sync/atomic"
	"time"
)

// H2C2SWriteMode selects synthetic C2S underlay behavior for localization gates.
type H2C2SWriteMode int

const (
	// H2C2SWakeImmediate: per-pkt SendProxiedIPDatagram (1 pipe Write / pkt after flush).
	H2C2SWakeImmediate H2C2SWriteMode = iota
	// H2C2SNoWakeVis: NoWake + Flush every batch (prod small-N vis coalesce).
	H2C2SNoWakeVis
)

// H2C2SWriteBenchResult is Mbps + underlay counters for C2S localization.
type H2C2SWriteBenchResult struct {
	Mode        H2C2SWriteMode
	IPPacketLen int
	Bytes       int64
	Mbps        float64
	WriteOK     uint64
	PipeWrites  uint64
	VisFlushes  uint64
	Flushes     uint64
}

// costlyUnderlayWriter models H2 upload-body Write tax (framing / syscall class):
// each Write pays a fixed CPU spin proportional to costUnits (not a sleep — stable CI).
type costlyUnderlayWriter struct {
	costUnits int
	writes    atomic.Uint64
	bytes     atomic.Uint64
	sink      []byte
}

func (w *costlyUnderlayWriter) Write(p []byte) (int, error) {
	// Spin ~costUnits * len bucket — Write count dominates (pipe tax), not byte copy.
	n := w.costUnits
	if n < 1 {
		n = 1
	}
	var x uint64
	for i := 0; i < n; i++ {
		x ^= uint64(i+1) * 0x9e3779b97f4a7c15
	}
	_ = x
	w.writes.Add(1)
	w.bytes.Add(uint64(len(p)))
	if cap(w.sink) < len(p) {
		w.sink = make([]byte, len(p))
	}
	copy(w.sink[:len(p)], p)
	return len(p), nil
}

// pacedUnderlayWriter serializes Writes through a depth-1 channel + paced drain.
// Models H2 body framing: each pipe Write waits for underlay progress (docker-class tax).
type pacedUnderlayWriter struct {
	ch     chan []byte
	writes atomic.Uint64
	bytes  atomic.Uint64
	done   chan struct{}
}

func newPacedUnderlayWriter(drainEvery time.Duration) *pacedUnderlayWriter {
	w := &pacedUnderlayWriter{
		ch:   make(chan []byte, 1),
		done: make(chan struct{}),
	}
	go func() {
		for {
			select {
			case <-w.done:
				return
			case p, ok := <-w.ch:
				if !ok {
					return
				}
				_ = p
				if drainEvery > 0 {
					time.Sleep(drainEvery)
				}
			}
		}
	}()
	return w
}

func (w *pacedUnderlayWriter) Write(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	select {
	case <-w.done:
		return 0, io.ErrClosedPipe
	case w.ch <- cp:
		w.writes.Add(1)
		w.bytes.Add(uint64(len(p)))
		return len(p), nil
	}
}

func (w *pacedUnderlayWriter) Close() error {
	select {
	case <-w.done:
	default:
		close(w.done)
	}
	return nil
}

// SyntheticH2WritePacketBench drives Conn.WritePacket* → h2CapsulePipeStream C2S.
// dst: nil → io.Discard; use costlyUnderlayWriter / pacedUnderlayWriter for underlay-tax asym class.
func SyntheticH2WritePacketBench(mode H2C2SWriteMode, ipPacketLen int, dur time.Duration, dst io.Writer) H2C2SWriteBenchResult {
	return SyntheticH2WritePacketBenchOpts(H2C2SWriteBenchOpts{
		Mode: mode, IPPacketLen: ipPacketLen, Dur: dur, Dst: dst,
	})
}

// H2C2SWriteBenchOpts configures SyntheticH2WritePacketBenchOpts (vis caps for N-curve gates).
type H2C2SWriteBenchOpts struct {
	Mode        H2C2SWriteMode
	IPPacketLen int
	Dur         time.Duration
	Dst         io.Writer
	// VisMaxPkts/Bytes override stream coalesce (0 → prod h2C2SVisMax*).
	VisMaxPkts  int
	VisMaxBytes int
	// LoopBatch is packets per FlushOutgoingDatagramSend (NoWake mode); 0 → 16.
	LoopBatch int
}

// SyntheticH2WritePacketBenchOpts is the full C2S wire bench (policy N overrides).
func SyntheticH2WritePacketBenchOpts(o H2C2SWriteBenchOpts) H2C2SWriteBenchResult {
	ipPacketLen := o.IPPacketLen
	if ipPacketLen <= 0 {
		ipPacketLen = 1200
	}
	dur := o.Dur
	if dur <= 0 {
		dur = 200 * time.Millisecond
	}
	dst := o.Dst
	if dst == nil {
		dst = io.Discard
	}
	batch := o.LoopBatch
	if batch < 1 {
		batch = 16
	}

	EnableCIPClientRelayStats()
	ResetCIPClientRelayStats()

	bodyR, bodyW := io.Pipe()
	str := &h2CapsulePipeStream{
		body:        bodyR,
		pipeW:       dst,
		visMaxPkts:  o.VisMaxPkts,
		visMaxBytes: o.VisMaxBytes,
	}
	conn := newProxiedConn(str, true)
	defer conn.Close()
	defer bodyR.Close()
	defer bodyW.Close()

	ip := make([]byte, ipPacketLen)
	ip[0] = 0x45
	ip[2] = byte(ipPacketLen >> 8)
	ip[3] = byte(ipPacketLen)
	ip[8] = 64
	ip[9] = 6
	ip[12], ip[13], ip[14], ip[15] = 10, 0, 0, 1
	ip[16], ip[17], ip[18], ip[19] = 10, 0, 0, 2

	start := time.Now()
	deadline := start.Add(dur)
	var total int64
	for time.Now().Before(deadline) {
		switch o.Mode {
		case H2C2SNoWakeVis:
			for i := 0; i < batch; i++ {
				ip[8] = 64
				if _, err := conn.WritePacketNoWake(ip); err != nil {
					break
				}
				total += int64(ipPacketLen)
			}
			conn.FlushOutgoingDatagramSend()
		default:
			for i := 0; i < batch; i++ {
				ip[8] = 64
				if _, err := conn.WritePacket(ip); err != nil {
					break
				}
				total += int64(ipPacketLen)
			}
		}
	}
	wall := time.Since(start)
	snap := SnapshotCIPClientRelayStats()
	var mbps float64
	if wall > 0 && total > 0 {
		mbps = float64(total*8) / wall.Seconds() / 1e6
	}
	return H2C2SWriteBenchResult{
		Mode:        o.Mode,
		IPPacketLen: ipPacketLen,
		Bytes:       total,
		Mbps:        mbps,
		WriteOK:     snap.WriteOK,
		PipeWrites:  snap.H2PipeWrite,
		VisFlushes:  snap.H2VisFlush,
		Flushes:     snap.Flush,
	}
}

// SyntheticH2C2SAsymLocalize runs wake vs NoWake-vis under paced underlay (Write-serialized).
// drainEvery is sleep per pipe Write on the drain side (underlay framing tax).
func SyntheticH2C2SAsymLocalize(ipPacketLen int, dur, drainEvery time.Duration) (wake, vis H2C2SWriteBenchResult, pipeRatio float64) {
	w := newPacedUnderlayWriter(drainEvery)
	defer w.Close()
	wake = SyntheticH2WritePacketBench(H2C2SWakeImmediate, ipPacketLen, dur, w)
	w2 := newPacedUnderlayWriter(drainEvery)
	defer w2.Close()
	vis = SyntheticH2WritePacketBench(H2C2SNoWakeVis, ipPacketLen, dur, w2)
	if vis.PipeWrites > 0 {
		pipeRatio = float64(vis.WriteOK) / float64(vis.PipeWrites)
	}
	return wake, vis, pipeRatio
}

// SyntheticH2C2SVisNCurve runs NoWake-vis at several VisMaxPkts under the same paced underlay.
func SyntheticH2C2SVisNCurve(ipPacketLen int, dur, drainEvery time.Duration, ns []int) []H2C2SWriteBenchResult {
	out := make([]H2C2SWriteBenchResult, 0, len(ns))
	for _, n := range ns {
		w := newPacedUnderlayWriter(drainEvery)
		r := SyntheticH2WritePacketBenchOpts(H2C2SWriteBenchOpts{
			Mode: H2C2SNoWakeVis, IPPacketLen: ipPacketLen, Dur: dur, Dst: w,
			VisMaxPkts: n, VisMaxBytes: 1 << 20, // pkt-cap only
			LoopBatch: max(n*4, 16),
		})
		w.Close()
		out = append(out, r)
	}
	return out
}

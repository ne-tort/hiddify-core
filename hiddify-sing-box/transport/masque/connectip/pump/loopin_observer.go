package pump

import (
	"sync/atomic"
	"time"
)

// LoopInObserver collects LoopIn iteration metrics (tests/diagnostics only; nil in prod).
type LoopInObserver struct {
	iters         atomic.Int64
	pkts          atomic.Int64
	flushes       atomic.Int64
	readCalls     atomic.Int64
	readNanos     atomic.Int64
	writeNanos    atomic.Int64
}

// LoopInStats is a point-in-time snapshot of LoopInObserver counters.
type LoopInStats struct {
	Iters        int64
	Pkts         int64
	Flushes      int64
	ReadCalls    int64
	ReadNanos    int64
	WriteNanos   int64
	PktsPerIter  float64
	PktsPerFlush float64
	ReadUsPerPkt float64
	WriteUsPerPkt float64
}

// Snapshot returns current observer counters and derived ratios.
func (o *LoopInObserver) Snapshot() LoopInStats {
	if o == nil {
		return LoopInStats{}
	}
	iters := o.iters.Load()
	pkts := o.pkts.Load()
	fl := o.flushes.Load()
	rc := o.readCalls.Load()
	rn := o.readNanos.Load()
	wn := o.writeNanos.Load()
	st := LoopInStats{
		Iters: iters, Pkts: pkts, Flushes: fl,
		ReadCalls: rc, ReadNanos: rn, WriteNanos: wn,
	}
	if iters > 0 {
		st.PktsPerIter = float64(pkts) / float64(iters)
	}
	if fl > 0 {
		st.PktsPerFlush = float64(pkts) / float64(fl)
	}
	if pkts > 0 {
		st.ReadUsPerPkt = float64(rn) / float64(pkts) / 1000.0
		st.WriteUsPerPkt = float64(wn) / float64(pkts) / 1000.0
	}
	return st
}

func (o *LoopInObserver) recordRead(d time.Duration) {
	if o == nil {
		return
	}
	o.readCalls.Add(1)
	o.readNanos.Add(d.Nanoseconds())
}

func (o *LoopInObserver) recordWrite(d time.Duration) {
	if o == nil {
		return
	}
	o.writeNanos.Add(d.Nanoseconds())
}

func (o *LoopInObserver) recordPkt() {
	if o == nil {
		return
	}
	o.pkts.Add(1)
}

func (o *LoopInObserver) endIter() {
	if o == nil {
		return
	}
	o.iters.Add(1)
}

func (o *LoopInObserver) recordFlush() {
	if o == nil {
		return
	}
	o.flushes.Add(1)
}

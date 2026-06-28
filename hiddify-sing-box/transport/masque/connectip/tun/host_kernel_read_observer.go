package tun

import "sync/atomic"

// HostKernelReadObserver collects KernelTunDevice ReadPacket metrics (tests/diagnostics only).
type HostKernelReadObserver struct {
	accepted atomic.Int64
	skipped  atomic.Int64
	zero     atomic.Int64
	readNano atomic.Int64
	bytes    atomic.Int64
}

// HostKernelReadStats is a snapshot of host-kernel tun read counters.
type HostKernelReadStats struct {
	Accepted   int64
	Skipped    int64
	Zero       int64
	ReadNanos  int64
	Bytes      int64
	ReadUsPerPkt float64
}

// Snapshot returns current read observer counters.
func (o *HostKernelReadObserver) Snapshot() HostKernelReadStats {
	if o == nil {
		return HostKernelReadStats{}
	}
	acc := o.accepted.Load()
	rn := o.readNano.Load()
	st := HostKernelReadStats{
		Accepted: acc, Skipped: o.skipped.Load(),
		Zero: o.zero.Load(), ReadNanos: rn, Bytes: o.bytes.Load(),
	}
	if acc > 0 {
		st.ReadUsPerPkt = float64(rn) / float64(acc) / 1000.0
	}
	return st
}

func (o *HostKernelReadObserver) recordRead(nanos int64, n int) {
	if o == nil {
		return
	}
	o.readNano.Add(nanos)
	if n <= 0 {
		o.zero.Add(1)
		return
	}
}

func (o *HostKernelReadObserver) recordAccepted(n int) {
	if o == nil || n <= 0 {
		return
	}
	o.accepted.Add(1)
	o.bytes.Add(int64(n))
}

func (o *HostKernelReadObserver) recordSkipped() {
	if o == nil {
		return
	}
	o.skipped.Add(1)
}

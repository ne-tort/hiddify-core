package pump

import (
	"testing"
	"time"
)

func TestClassifyLoopInBound(t *testing.T) {
	t.Parallel()
	readBound := LoopInStats{Pkts: 1000, ReadUsPerPkt: 18, WriteUsPerPkt: 1, FlushUsPerPkt: 1}
	if got := ClassifyLoopInBound(readBound); got != LoopInBoundRead {
		t.Fatalf("read-bound: got %q", got)
	}
	flushBound := LoopInStats{Pkts: 1000, ReadUsPerPkt: 1, WriteUsPerPkt: 2, FlushUsPerPkt: 15}
	if got := ClassifyLoopInBound(flushBound); got != LoopInBoundWrite {
		t.Fatalf("flush-bound: got %q", got)
	}
}

func TestLoopInObserverFlushTiming(t *testing.T) {
	t.Parallel()
	obs := &LoopInObserver{}
	obs.recordPkt()
	obs.recordFlush(5 * time.Microsecond)
	st := obs.Snapshot()
	if st.Flushes != 1 || st.FlushUsPerPkt < 4 || st.FlushUsPerPkt > 6 {
		t.Fatalf("flush timing: %+v", st)
	}
}

func TestLoopInObserverNilReceiverNoOp(t *testing.T) {
	t.Parallel()
	var obs *LoopInObserver
	obs.recordRead(time.Millisecond)
	obs.recordWrite(time.Millisecond)
	obs.recordPkt()
	obs.recordFlush(time.Millisecond)
	obs.endIter()
	if st := obs.Snapshot(); st.Pkts != 0 || st.Iters != 0 {
		t.Fatalf("nil observer must stay zero: %+v", st)
	}
}

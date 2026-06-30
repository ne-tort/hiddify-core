package pump

// LoopInBoundClass labels the dominant LoopIn stage from metrics snapshot.
type LoopInBoundClass string

const (
	LoopInBoundRead    LoopInBoundClass = "read_bound"
	LoopInBoundWrite   LoopInBoundClass = "flush_bound"
	LoopInBoundMixed   LoopInBoundClass = "mixed_bound"
	LoopInBoundUnknown LoopInBoundClass = "unknown"
)

const loopInBoundUsThreshold = 3.0

// ClassifyLoopInBound picks dominant stage from per-pkt micro-budgets.
func ClassifyLoopInBound(st LoopInStats) LoopInBoundClass {
	if st.Pkts < 100 {
		return LoopInBoundUnknown
	}
	readDom := st.ReadUsPerPkt >= loopInBoundUsThreshold
	writeDom := st.WriteUsPerPkt >= loopInBoundUsThreshold
	flushDom := st.FlushUsPerPkt >= loopInBoundUsThreshold
	writeFlush := writeDom || flushDom
	switch {
	case readDom && writeFlush:
		return LoopInBoundMixed
	case readDom:
		return LoopInBoundRead
	case writeFlush:
		return LoopInBoundWrite
	default:
		return LoopInBoundUnknown
	}
}

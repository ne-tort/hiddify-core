package pump

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// LoopInBoundClass labels the dominant LoopIn stage from metrics snapshot.
type LoopInBoundClass string

const (
	LoopInBoundRead    LoopInBoundClass = "read_bound"
	LoopInBoundWrite   LoopInBoundClass = "flush_bound"
	LoopInBoundMixed   LoopInBoundClass = "mixed_bound"
	LoopInBoundUnknown LoopInBoundClass = "unknown"
)

const loopInBoundUsThreshold = 3.0

// LoopInMetricsEnabled reports Docker/synth iter-budget diagnostics (HIDDIFY_MASQUE_CONNECT_IP_LOOPIN_METRICS=1).
func LoopInMetricsEnabled() bool {
	return strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_LOOPIN_METRICS")) == "1"
}

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

// FormatLoopInMetricsLine returns a single grep-friendly log line for Docker iter breakdown.
func FormatLoopInMetricsLine(st LoopInStats, hostAccepted int64, hostReadUs float64) string {
	pps := 0.0
	if st.IterUsPerPkt > 0 && st.Pkts > 0 {
		pps = 1e6 / st.IterUsPerPkt
	}
	return fmt.Sprintf(
		"connect-ip LoopIn metrics: bound=%s pkts=%d iters=%d pps=%.0f read_us/pkt=%.1f write_us/pkt=%.1f flush_us/pkt=%.1f iter_us/pkt=%.1f pkts/iter=%.2f pkts/flush=%.2f host_accepted=%d host_read_us/pkt=%.1f",
		ClassifyLoopInBound(st), st.Pkts, st.Iters, pps,
		st.ReadUsPerPkt, st.WriteUsPerPkt, st.FlushUsPerPkt, st.IterUsPerPkt,
		st.PktsPerIter, st.PktsPerFlush, hostAccepted, hostReadUs,
	)
}

// LogLoopInMetrics emits one metrics line to the standard logger.
func LogLoopInMetrics(st LoopInStats, hostAccepted int64, hostReadUs float64) {
	log.Print(FormatLoopInMetricsLine(st, hostAccepted, hostReadUs))
}

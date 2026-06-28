package tun

import (
	"context"
	"sync"
	"time"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

// Docker connect-ip-h3-tun upload identity (PERF-UP localize).
const (
	Upload524CeilingMbps     = 524.0
	Upload524SegBytes        = 1310
	Upload524PPS             = 50000
	Upload524PktSpacing      = time.Second / Upload524PPS // 20µs
	Upload524MbpsBandLo      = 470.0
	Upload524MbpsBandHi      = 580.0
	Upload524PPSBandLo       = 45000
	Upload524PPSBandHi       = 55000
	Upload524PktsPerFlushMax = 1.15
)

func upload524MbpsFromPPS(pps float64, segBytes int) float64 {
	if pps <= 0 || segBytes <= 0 {
		return 0
	}
	return pps * float64(segBytes) * 8 / 1e6
}

// upload524SpinDelay busy-waits until spacing elapses (Windows time.Sleep(20µs) ≈ 0.5–1ms).
func upload524SpinDelay(spacing time.Duration) {
	if spacing <= 0 {
		return
	}
	deadline := time.Now().Add(spacing)
	for time.Now().Before(deadline) {
	}
}

type upload524PumpMeter struct {
	Writes       int64
	Flushes      int64
	Elapsed      time.Duration
	PPS          float64
	Mbps         float64
	PktsPerFlush float64
	LoopIn       cippump.LoopInStats
	HostRead     HostKernelReadStats
	Bound        UploadBoundClass
}

// UploadBoundClass classifies which stage limits upload throughput in synth gates.
type UploadBoundClass string

const (
	UploadBoundRead    UploadBoundClass = "read_bound"
	UploadBoundFlush   UploadBoundClass = "flush_bound"
	UploadBoundBoth    UploadBoundClass = "both_bound"
	UploadBoundUnpaced UploadBoundClass = "unpaced"
)

const (
	uploadBoundUsThreshold = 12.0 // µs/pkt — dominant stage when above this
)

// classifyUploadBound labels synth harness by read vs write/flush micro-budget.
func classifyUploadBound(m upload524PumpMeter) UploadBoundClass {
	if m.Mbps > Upload524MbpsBandHi {
		return UploadBoundUnpaced
	}
	readUs := m.LoopIn.ReadUsPerPkt
	writeUs := m.LoopIn.WriteUsPerPkt
	readDom := readUs >= uploadBoundUsThreshold
	writeDom := writeUs >= uploadBoundUsThreshold
	switch {
	case readDom && writeDom:
		return UploadBoundBoth
	case readDom:
		return UploadBoundRead
	case writeDom:
		return UploadBoundFlush
	default:
		return UploadBoundBoth
	}
}

// hostEgressReadPaced spaces successful ReadPacket returns by spacing (Linux sub-ms; prod kernel rate identity).
func hostEgressReadPaced(spacing time.Duration, seg []byte) HostEgressReader {
	var mu sync.Mutex
	var next time.Time
	return func(ctx context.Context, buf []byte) (int, error) {
		mu.Lock()
		now := time.Now()
		if next.IsZero() {
			next = now
		}
		if wait := next.Sub(now); wait > 0 {
			mu.Unlock()
			upload524SpinDelay(wait)
			select {
			case <-ctx.Done():
				return 0, context.Cause(ctx)
			default:
			}
			mu.Lock()
		}
		next = time.Now().Add(spacing)
		mu.Unlock()
		return copy(buf, seg), nil
	}
}

// hostEgressDepth1Paced feeds one MSS segment at spacing with channel depth 1 (prod kernel read() parity).
func hostEgressDepth1Paced(spacing time.Duration, seg []byte) (HostEgressReader, context.CancelFunc) {
	staged := make(chan []byte, 1)
	feedCtx, feedCancel := context.WithCancel(context.Background())
	go func() {
		for {
			select {
			case <-feedCtx.Done():
				return
			case staged <- seg:
				upload524SpinDelay(spacing)
			}
		}
	}()
	read := HostEgressReader(func(ctx context.Context, buf []byte) (int, error) {
		select {
		case pkt, ok := <-staged:
			if !ok {
				return 0, ctx.Err()
			}
			return copy(buf, pkt), nil
		case <-ctx.Done():
			return 0, context.Cause(ctx)
		}
	})
	return read, feedCancel
}

// hostEgressInfinite returns the same MSS segment without pacing (upper bound for pump+wire).
func hostEgressInfinite(seg []byte) HostEgressReader {
	return func(_ context.Context, buf []byte) (int, error) {
		return copy(buf, seg), nil
	}
}

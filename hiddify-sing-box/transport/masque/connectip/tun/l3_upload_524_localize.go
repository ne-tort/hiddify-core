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
	Upload524PPSBandLo       = 35000
	Upload524PPSBandHi       = 55000
	Upload524PktsPerFlushMax = 1.15
	// UploadDODMbps is connect-ip-h3-tun single-flow DoD @ Docker 0ms.
	UploadDODMbps = 1000.0
	// UploadDODIterBudget is per-pkt LoopIn budget for ≥1000 @ 1310 B (≈95.4 kpps).
	UploadDODIterBudget = 10500 * time.Nanosecond
	// Upload524IterBudget is verified prod steady-state identity (50 kpps).
	Upload524IterBudget = 20000 * time.Nanosecond
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

// hostEgressDepth1Immediate feeds one segment at a time; no spacing (depth-1 always ready when LoopIn reads).
func hostEgressDepth1Immediate(seg []byte) (HostEgressReader, context.CancelFunc) {
	return hostEgressDepth1Paced(0, seg)
}

// hostEgressDepth1WithReadWork simulates syscall/kernel work on each successful read (depth-1 immediate feed).
func hostEgressDepth1WithReadWork(seg []byte, readWork time.Duration) (HostEgressReader, context.CancelFunc) {
	staged := make(chan []byte, 1)
	feedCtx, feedCancel := context.WithCancel(context.Background())
	go func() {
		for {
			select {
			case <-feedCtx.Done():
				return
			case staged <- seg:
			}
		}
	}()
	read := HostEgressReader(func(ctx context.Context, buf []byte) (int, error) {
		select {
		case pkt, ok := <-staged:
			if !ok {
				return 0, ctx.Err()
			}
			if readWork > 0 {
				upload524SpinDelay(readWork)
			}
			return copy(buf, pkt), nil
		case <-ctx.Done():
			return 0, context.Cause(ctx)
		}
	})
	return read, feedCancel
}

// hostSyscallBatchFeed delivers batch segments per simulated syscall (prefetch parity).
type hostSyscallBatchFeed struct {
	mu        sync.Mutex
	q         [][]byte
	seg       []byte
	syscallUs time.Duration
	batch     int
}

func newHostSyscallBatchFeed(seg []byte, batch int, syscallUs time.Duration) *hostSyscallBatchFeed {
	if batch < 1 {
		batch = 1
	}
	return &hostSyscallBatchFeed{seg: seg, batch: batch, syscallUs: syscallUs}
}

func (f *hostSyscallBatchFeed) read(ctx context.Context, buf []byte) (int, error) {
	for {
		f.mu.Lock()
		if len(f.q) > 0 {
			pkt := f.q[0]
			f.q = f.q[1:]
			f.mu.Unlock()
			return copy(buf, pkt), nil
		}
		f.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if f.syscallUs > 0 {
			upload524SpinDelay(f.syscallUs)
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		f.mu.Lock()
		for i := 0; i < f.batch; i++ {
			f.q = append(f.q, f.seg)
		}
		f.mu.Unlock()
	}
}

// hostEgressKernelQueue models paced kernel tun egress: producer adds MSS on a fixed
// spacing while reads pop instantly; coalesce drain can take a queued pkt without syscall.
type hostEgressKernelQueue struct {
	mu        sync.Mutex
	q         [][]byte
	seg       []byte
	spacing   time.Duration
	minDepth  int
}

func newHostEgressKernelQueue(seg []byte, spacing time.Duration, minDepth int) (*hostEgressKernelQueue, context.CancelFunc) {
	if minDepth < 1 {
		minDepth = 1
	}
	h := &hostEgressKernelQueue{seg: seg, spacing: spacing, minDepth: minDepth}
	ctx, cancel := context.WithCancel(context.Background())
	go h.producer(ctx)
	return h, cancel
}

func (h *hostEgressKernelQueue) producer(ctx context.Context) {
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		h.mu.Lock()
		depth := len(h.q)
		h.mu.Unlock()
		if depth >= h.minDepth {
			upload524SpinDelay(h.spacing / 8)
			continue
		}
		upload524SpinDelay(h.spacing)
		if err := ctx.Err(); err != nil {
			return
		}
		h.mu.Lock()
		h.q = append(h.q, h.seg)
		h.mu.Unlock()
	}
}

func (h *hostEgressKernelQueue) read(ctx context.Context, buf []byte) (int, error) {
	for {
		h.mu.Lock()
		if len(h.q) > 0 {
			pkt := h.q[0]
			h.q = h.q[1:]
			h.mu.Unlock()
			return copy(buf, pkt), nil
		}
		h.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		upload524SpinDelay(h.spacing / 16)
	}
}

// hostEgressInfinite returns the same MSS segment without pacing (upper bound for pump+wire).
func hostEgressInfinite(seg []byte) HostEgressReader {
	return func(_ context.Context, buf []byte) (int, error) {
		return copy(buf, seg), nil
	}
}

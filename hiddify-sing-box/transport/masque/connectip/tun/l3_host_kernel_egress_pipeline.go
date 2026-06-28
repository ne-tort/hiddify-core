package tun

import (
	"context"
	"sync"
	"time"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

// PERF-2 localization only — not wired in RunPump (Docker 524 unchanged; download regressed when enabled).
const (
	hostKernelEgressPipeDepth     = 512
	hostKernelEgressPipeFlushMin  = 8
	hostKernelEgressPipeFlushWait = 200 * time.Microsecond
)

type hostKernelEgressPipeline struct {
	ctx     context.Context
	cancel  context.CancelFunc
	ch      chan []byte
	writer  PacketWriter
	flushFn func()
	pool    *cippump.NetBuffer
	wg      sync.WaitGroup
}

func newHostKernelEgressPipeline(
	parent context.Context,
	writer PacketWriter,
	flushFn func(),
	pool *cippump.NetBuffer,
) *hostKernelEgressPipeline {
	if parent == nil || writer == nil || flushFn == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(parent)
	return &hostKernelEgressPipeline{
		ctx:     ctx,
		cancel:  cancel,
		ch:      make(chan []byte, hostKernelEgressPipeDepth),
		writer:  writer,
		flushFn: flushFn,
		pool:    pool,
	}
}

func (p *hostKernelEgressPipeline) start() {
	if p == nil {
		return
	}
	p.wg.Add(1)
	go p.run()
}

func (p *hostKernelEgressPipeline) stop() {
	if p == nil {
		return
	}
	p.cancel()
	p.wg.Wait()
}

func (p *hostKernelEgressPipeline) submit(pkt []byte) (retained bool, err error) {
	if p == nil || len(pkt) == 0 {
		return false, nil
	}
	select {
	case p.ch <- pkt:
		return true, nil
	case <-p.ctx.Done():
		return false, context.Cause(p.ctx)
	}
}

func (p *hostKernelEgressPipeline) beforeSync() {
	if p == nil {
		return
	}
	deadline := time.Now().Add(50 * time.Millisecond)
	for len(p.ch) > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Microsecond)
	}
	p.flushFn()
}

func (p *hostKernelEgressPipeline) run() {
	defer p.wg.Done()
	pending := 0
	lastFlush := time.Now()
	flush := func() {
		if pending == 0 {
			return
		}
		p.flushFn()
		pending = 0
		lastFlush = time.Now()
	}
	ticker := time.NewTicker(hostKernelEgressPipeFlushWait / 2)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			for {
				select {
				case pkt := <-p.ch:
					p.writeOne(pkt)
					pending++
				default:
					flush()
					return
				}
			}
		case pkt := <-p.ch:
			p.writeOne(pkt)
			pending++
			if pending >= hostKernelEgressPipeFlushMin || time.Since(lastFlush) >= hostKernelEgressPipeFlushWait {
				flush()
			}
		case <-ticker.C:
			if pending > 0 && time.Since(lastFlush) >= hostKernelEgressPipeFlushWait {
				flush()
			}
		}
	}
}

func (p *hostKernelEgressPipeline) writeOne(pkt []byte) {
	retained, _, err := writeHostKernelEgressInPlace(p.writer, pkt)
	if err != nil || retained || p.pool == nil {
		return
	}
	p.pool.Put(pkt[:cap(pkt)])
}

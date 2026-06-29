package pump

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"time"
)

// RunTunnelBatch runs symmetric Device↔Conn pump loops with batch LoopIn read (upload DoD path).
// LoopOut is identical to RunTunnel; LoopIn uses ReadEgressBatch → N× write → one OnLoopInEnd.
// Ref: docs/masque/architecture/CONNECT-IP-UPLOAD-BATCH-READ.md
func RunTunnelBatch(ctx context.Context, device BatchTunnelDevice, conn PacketConn, opts TunnelOptions, maxBatch int) error {
	if device == nil || conn == nil {
		return nil
	}
	if maxBatch < 1 {
		maxBatch = DefaultLoopInMaxBatch
	}
	opts = NormalizeTunnelOptions(opts)
	// Batch path replaces coalesce poll/drain — one syscall boundary read per iter.
	opts.LoopInUsqueImmediate = true
	opts.LoopInDrainOnly = false
	opts.LoopInCoalescePoll = 0
	// Host-kernel ACK return: drain queued ingress without 2ms blocking batch (LoopOutSkipBatchDrain).
	if opts.LoopOutSkipBatchDrain && !opts.LegacyCMBatchDrain {
		opts.LoopOutUsqueImmediate = false
	}

	mtu := opts.MTU
	if mtu <= 0 {
		mtu = DefaultTunnelMTU
	}
	pool := opts.NetBuffer
	if pool == nil {
		pool = NewNetBuffer(mtu)
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		errCh <- runLoopInBatch(runCtx, device, conn, opts, pool, maxBatch)
	}()
	go func() {
		defer wg.Done()
		errCh <- runLoopOut(runCtx, device, conn, opts, pool)
	}()
	var firstErr error
	select {
	case firstErr = <-errCh:
		cancel()
	case <-runCtx.Done():
		firstErr = context.Cause(runCtx)
	}
	wg.Wait()
	_ = conn.Close()
	if firstErr != nil && !errors.Is(firstErr, context.Canceled) {
		return firstErr
	}
	return context.Cause(ctx)
}

func runLoopInBatch(ctx context.Context, device BatchTunnelDevice, conn PacketConn, opts TunnelOptions, pool *NetBuffer, maxBatch int) error {
	slots := make([]EgressSlot, maxBatch)
	obs := opts.LoopInObserver

	for {
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
		for i := range slots {
			if slots[i].Buf == nil {
				slots[i].Buf = pool.Get()
			}
			slots[i].Len = 0
		}

		var rStart time.Time
		if obs != nil {
			rStart = time.Now()
		}
		n, err := device.ReadEgressBatch(ctx, slots, maxBatch)
		if obs != nil {
			obs.recordRead(time.Since(rStart))
		}
		if err != nil {
			if ctx.Err() != nil {
				return context.Cause(ctx)
			}
			if IsRetryablePacketReadError(err) {
				runtime.Gosched()
				continue
			}
			return err
		}
		if n <= 0 {
			runtime.Gosched()
			continue
		}

		for i := 0; i < n; i++ {
			pktLen := slots[i].Len
			if pktLen <= 0 {
				continue
			}
			var wStart time.Time
			if obs != nil {
				wStart = time.Now()
			}
			retained, err := writeLoopInPacket(device, conn, slots[i].Buf[:pktLen])
			if obs != nil {
				obs.recordWrite(time.Since(wStart))
				obs.recordPkt()
			}
			if err != nil {
				return err
			}
			if retained {
				slots[i].Buf = nil
			}
		}
		for i := range slots {
			if slots[i].Buf != nil {
				pool.Put(slots[i].Buf)
				slots[i].Buf = nil
			}
		}

		if opts.OnLoopInEnd != nil {
			var flushStart time.Time
			if obs != nil {
				flushStart = time.Now()
			}
			opts.OnLoopInEnd()
			if obs != nil {
				obs.recordFlush(time.Since(flushStart))
			}
		}
		if obs != nil {
			obs.endIter()
		}
	}
}

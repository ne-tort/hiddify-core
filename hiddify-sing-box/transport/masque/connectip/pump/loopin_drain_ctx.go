package pump

import (
	"context"
	"time"
)

// loopInExpiredDrainCtx is a reusable already-expired context for zero-timeout tun/prefetch drain.
// Avoids per-coalesce context.WithTimeout allocations in host-kernel LoopIn hot path.
var loopInExpiredDrainCtx context.Context
var loopInExpiredDrainCancel context.CancelFunc

func init() {
	loopInExpiredDrainCtx, loopInExpiredDrainCancel = context.WithCancel(context.Background())
	loopInExpiredDrainCancel()
}

// LoopInExpiredDrainCtx returns a context that is always canceled (queue-only drain; no tun read).
func LoopInExpiredDrainCtx() context.Context {
	return loopInExpiredDrainCtx
}

// LoopInNonblockingDrainCtx returns a context with a past deadline (EAGAIN tun read, not canceled).
// Use in read-ahead pump drain loops only — not on LoopIn hot path.
func LoopInNonblockingDrainCtx() context.Context {
	ctx, _ := context.WithDeadline(context.Background(), time.Unix(0, 0))
	return ctx
}

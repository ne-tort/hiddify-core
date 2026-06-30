package tun

import "context"

// hostEgressSingleBatch adapts one HostEgressReader syscall into HostEgressBatchReader (1 buf/ReadBatch).
// Prod overrides via SetHostEgressBatch (ReadHostEgressBatch); default keeps batch-only ReadEgressBatch shape.
type hostEgressSingleBatch struct {
	d *KernelTunDevice
}

func (b hostEgressSingleBatch) ReadBatch(ctx context.Context, bufs [][]byte, maxN int) (int, error) {
	if b.d == nil || maxN <= 0 || len(bufs) == 0 {
		return 0, nil
	}
	n, err := b.d.readLocked(ctx, bufs[0])
	if err != nil || n <= 0 {
		return 0, err
	}
	return 1, nil
}

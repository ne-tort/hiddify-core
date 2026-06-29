package tun

import (
	"context"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

// HostEgressBatchReader reads up to maxN kernel egress datagrams per syscall boundary.
// First pkt may block per ctx; additional pkts come from prefetch/drain without blocking.
// Ref: docs/masque/architecture/CONNECT-IP-UPLOAD-BATCH-READ.md
type HostEgressBatchReader interface {
	ReadBatch(ctx context.Context, bufs [][]byte, maxN int) (n int, err error)
}

// hostEgressReaderBatch adapts legacy single-pkt HostEgressReader to ReadBatch.
type hostEgressReaderBatch struct {
	read HostEgressReader
}

func HostEgressReaderAsBatch(read HostEgressReader) HostEgressBatchReader {
	if read == nil {
		return nil
	}
	return hostEgressReaderBatch{read: read}
}

// AdaptNativeHostEgressBatch wraps sing-tun ReadHostEgressBatch for KernelTunDevice batch LoopIn.
func AdaptNativeHostEgressBatch(read func(context.Context, [][]byte, int) (int, error)) HostEgressBatchReader {
	if read == nil {
		return nil
	}
	return nativeHostEgressBatchAdapter{read: read}
}

type nativeHostEgressBatchAdapter struct {
	read func(context.Context, [][]byte, int) (int, error)
}

func (a nativeHostEgressBatchAdapter) ReadBatch(ctx context.Context, bufs [][]byte, maxN int) (int, error) {
	return a.read(ctx, bufs, maxN)
}

func (h hostEgressReaderBatch) ReadBatch(ctx context.Context, bufs [][]byte, maxN int) (int, error) {
	if maxN < 1 || len(bufs) == 0 {
		return 0, nil
	}
	if maxN > len(bufs) {
		maxN = len(bufs)
	}
	n, err := h.read(ctx, bufs[0])
	if err != nil || n <= 0 {
		return 0, err
	}
	got := 1
	drain := cippump.LoopInExpiredDrainCtx()
	for got < maxN {
		nn, err2 := h.read(drain, bufs[got])
		if err2 != nil || nn <= 0 {
			break
		}
		got++
	}
	return got, nil
}

func (f *hostSyscallBatchFeed) ReadBatch(ctx context.Context, bufs [][]byte, maxN int) (int, error) {
	return f.readBatch(ctx, bufs, maxN)
}

func (f *hostSyscallBatchFeed) readBatch(ctx context.Context, bufs [][]byte, maxN int) (int, error) {
	if f == nil || maxN < 1 || len(bufs) == 0 {
		return 0, nil
	}
	if maxN > len(bufs) {
		maxN = len(bufs)
	}
	n, err := f.read(ctx, bufs[0])
	if err != nil || n <= 0 {
		return 0, err
	}
	got := 1
	drain := cippump.LoopInExpiredDrainCtx()
	for got < maxN {
		nn, err2 := f.read(drain, bufs[got])
		if err2 != nil || nn <= 0 {
			break
		}
		got++
	}
	return got, nil
}

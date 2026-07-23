package tun

import (
	"context"
	"testing"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

func TestUsquePumpOptionsStackOnLoopInEnd(t *testing.T) {
	b := NewL3OverlayBridge(func([]byte) (int, error) { return 0, nil }, &mockL3Writer{}, nil, OverlayNAT{})
	opts := b.usquePumpOptions(func() {})
	if opts.OnLoopInEnd == nil {
		t.Fatal("OnLoopInEnd want wired for stack inject")
	}
	_ = cippump.NormalizeTunnelOptions(opts)
}

func TestHostKernelBatchPumpOptionsLoopOutCoalesce(t *testing.T) {
	b := NewL3OverlayBridge(nil, &mockL3Writer{}, nil, OverlayNAT{})
	b.SetHostEgressRead(func(context.Context, []byte) (int, error) { return 0, nil }, nil)
	opts := b.hostKernelBatchPumpOptions(nil)
	if !opts.LoopOutSkipBatchDrain {
		t.Fatal("LoopOutSkipBatchDrain want true for host-kernel batch ACK coalesce")
	}
	opts = cippump.NormalizeTunnelOptions(opts)
	if opts.LoopOutSkipBatchDrain {
		opts.LoopOutUsqueImmediate = false
	}
	if opts.LoopOutUsqueImmediate {
		t.Fatal("LoopOutUsqueImmediate want false when LoopOutSkipBatchDrain (zero-timeout wire drain)")
	}
}

func TestUsquePumpOptionsHostKernelFallbackNoStackFlush(t *testing.T) {
	b := NewL3OverlayBridge(nil, &mockL3Writer{}, nil, OverlayNAT{})
	b.SetHostEgressRead(func(context.Context, []byte) (int, error) { return 0, nil }, nil)
	opts := b.usquePumpOptions(func() {})
	// Host-kernel prod uses RunTunnelBatch + hostKernelBatchPumpOptions for OnLoopInEnd;
	// usquePumpOptions must not attach stack-style flush here.
	if opts.OnLoopInEnd != nil {
		t.Fatal("OnLoopInEnd want nil on host-kernel usquePumpOptions fallback")
	}
	if !opts.LoopOutUsqueImmediate {
		t.Fatal("LoopOutUsqueImmediate want true after Normalize")
	}
}

func TestLoopInMaxBatchOverride(t *testing.T) {
	b := NewL3OverlayBridge(nil, &mockL3Writer{}, nil, OverlayNAT{})
	if got := b.loopInMaxBatchOrDefault(); got != cippump.DefaultLoopInMaxBatch {
		t.Fatalf("default batch=%d want %d", got, cippump.DefaultLoopInMaxBatch)
	}
	b.SetLoopInMaxBatch(cippump.H2HostKernelLoopInMaxBatch)
	if got := b.loopInMaxBatchOrDefault(); got != cippump.H2HostKernelLoopInMaxBatch {
		t.Fatalf("H2 batch=%d want %d", got, cippump.H2HostKernelLoopInMaxBatch)
	}
}

package tun

import (
	"context"
	"testing"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

func TestUsquePumpOptionsStackImmediateLoopIn(t *testing.T) {
	b := NewL3OverlayBridge(func([]byte) (int, error) { return 0, nil }, &mockL3Writer{}, nil, OverlayNAT{})
	opts := b.usquePumpOptions(func() {})
	if !opts.LoopInUsqueImmediate {
		t.Fatalf("LoopInUsqueImmediate=%v want true for stack inject", opts.LoopInUsqueImmediate)
	}
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
	if opts.LoopOutSkipBatchDrain && !opts.LegacyCMBatchDrain {
		opts.LoopOutUsqueImmediate = false
	}
	if opts.LoopOutUsqueImmediate {
		t.Fatal("LoopOutUsqueImmediate want false when LoopOutSkipBatchDrain (zero-timeout wire drain)")
	}
}

func TestUsquePumpOptionsHostKernelFallbackImmediate(t *testing.T) {
	b := NewL3OverlayBridge(nil, &mockL3Writer{}, nil, OverlayNAT{})
	b.SetHostEgressRead(func(context.Context, []byte) (int, error) { return 0, nil }, nil)
	opts := b.usquePumpOptions(nil)
	if !opts.LoopInUsqueImmediate {
		t.Fatal("LoopInUsqueImmediate want true (prod uses RunTunnelBatch; fallback is usque-shaped)")
	}
}

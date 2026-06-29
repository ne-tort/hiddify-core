package tun

import (
	"context"
	"testing"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

func TestUsquePumpOptionsHostKernelCoalescesLoopIn(t *testing.T) {
	b := NewL3OverlayBridge(nil, &mockL3Writer{}, nil, OverlayNAT{})
	b.SetHostEgressRead(func(context.Context, []byte) (int, error) { return 0, nil }, nil)
	opts := b.usquePumpOptions(nil)
	if opts.LoopInUsqueImmediate {
		t.Fatal("LoopInUsqueImmediate want false for host-kernel bulk coalesce")
	}
	if !opts.LoopInDrainOnly {
		t.Fatal("LoopInDrainOnly want true for host-kernel (zero-timeout prefetch drain)")
	}
	if opts.LoopOutYieldAfterWrite {
		t.Fatal("LoopOutYieldAfterWrite want false for host-kernel bulk upload")
	}
	if opts.LoopInCoalescePoll != 0 {
		t.Fatalf("LoopInCoalescePoll=%v want 0 (drain-only, no blocking poll)", opts.LoopInCoalescePoll)
	}
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

func TestUsquePumpOptionsStackImmediateLoopIn(t *testing.T) {
	b := NewL3OverlayBridge(func([]byte) (int, error) { return 0, nil }, &mockL3Writer{}, nil, OverlayNAT{})
	opts := b.usquePumpOptions(func() {})
	if opts.LoopInUsqueImmediate != true {
		t.Fatalf("LoopInUsqueImmediate=%v want true for stack inject", opts.LoopInUsqueImmediate)
	}
	if opts.OnLoopInEnd == nil {
		t.Fatal("OnLoopInEnd want wired for stack inject")
	}
	_ = cippump.NormalizeTunnelOptions(opts)
}

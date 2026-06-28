package tun

import (
	"context"
	"testing"
	"time"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

func TestUsquePumpOptionsHostKernelCoalescesLoopIn(t *testing.T) {
	b := NewL3OverlayBridge(nil, &mockL3Writer{}, nil, OverlayNAT{})
	b.SetHostEgressRead(func(context.Context, []byte) (int, error) { return 0, nil }, nil)
	opts := b.usquePumpOptions(nil)
	if opts.LoopInUsqueImmediate {
		t.Fatal("LoopInUsqueImmediate want false for host-kernel bulk coalesce")
	}
	if !opts.LoopOutYieldAfterWrite {
		t.Fatal("LoopOutYieldAfterWrite want true for host-kernel")
	}
	if !opts.LoopOutYieldAfterWrite {
		t.Fatal("LoopOutYieldAfterWrite want true for host-kernel")
	}
	if opts.LoopInCoalescePoll != 100*time.Microsecond {
		t.Fatalf("LoopInCoalescePoll=%v want 100µs", opts.LoopInCoalescePoll)
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

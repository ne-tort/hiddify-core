package http2

import (
	"bufio"
	"bytes"
	"sync"
	"testing"
)

func TestMasqueDownloadPokeReceiveWindowOnce(t *testing.T) {
	SetMasqueDownloadEagerWindowEnabled(true)
	t.Cleanup(func() { SetMasqueDownloadEagerWindowEnabled(false) })

	var wire bytes.Buffer
	bw := bufio.NewWriter(&wire)
	cc := &ClientConn{
		bw: bw,
		fr: NewFramer(bw, nil),
	}
	cc.cond = sync.NewCond(&cc.mu)
	cs := &clientStream{
		masqueExtendedConnect: true,
		cc:                    cc,
		ID:                    1,
	}
	cc.mu.Lock()
	cs.inflow.init(65535)
	cc.inflow.init(65535)
	cc.mu.Unlock()

	cs.masquePokeDownloadReceiveWindowOnce()
	cs.masquePokeDownloadReceiveWindowOnce() // Once: no second WU storm

	if wire.Len() == 0 {
		t.Fatal("expected WINDOW_UPDATE frames after poke")
	}
}

func TestMasqueDownloadRearmOnBudget(t *testing.T) {
	SetMasqueDownloadEagerWindowEnabled(true)
	t.Cleanup(func() { SetMasqueDownloadEagerWindowEnabled(false) })

	var wire bytes.Buffer
	bw := bufio.NewWriter(&wire)
	cc := &ClientConn{
		bw: bw,
		fr: NewFramer(bw, nil),
	}
	cc.cond = sync.NewCond(&cc.mu)
	cs := &clientStream{
		masqueExtendedConnect: true,
		cc:                    cc,
		ID:                    1,
	}
	cc.mu.Lock()
	// Start below cap so rearm poke can still grow avail.
	cs.inflow.init(masqueDownloadWindowLowWater + 1)
	cc.inflow.init(masqueDownloadWindowLowWater + 1)
	cc.mu.Unlock()

	cs.masquePokeDownloadReceiveWindowOnce()
	afterBootstrap := wire.Len()
	if afterBootstrap == 0 {
		t.Fatal("expected bootstrap poke WINDOW_UPDATE")
	}

	// Under rearm budget — no additional frames.
	cs.masqueMaybeRearmDownloadReceiveWindow(1024)
	if wire.Len() != afterBootstrap {
		t.Fatalf("unexpected rearm under budget: wire %d -> %d", afterBootstrap, wire.Len())
	}

	// Cross 4 MiB body boundary → extra poke.
	cs.masqueMaybeRearmDownloadReceiveWindow(masqueDownloadRearmEveryBytes)
	if wire.Len() <= afterBootstrap {
		t.Fatal("expected rearm WINDOW_UPDATE after crossing body budget")
	}
}

func TestMasqueDownloadRearmOnLowWater(t *testing.T) {
	SetMasqueDownloadEagerWindowEnabled(true)
	t.Cleanup(func() { SetMasqueDownloadEagerWindowEnabled(false) })

	var wire bytes.Buffer
	bw := bufio.NewWriter(&wire)
	cc := &ClientConn{
		bw: bw,
		fr: NewFramer(bw, nil),
	}
	cc.cond = sync.NewCond(&cc.mu)
	cs := &clientStream{
		masqueExtendedConnect: true,
		cc:                    cc,
		ID:                    1,
		masqueDownloadBodySeen: 1, // skip Once confusion; call rearm path only
	}
	cc.mu.Lock()
	cs.inflow.init(1024) // below low-water
	cc.inflow.init(1024)
	cc.mu.Unlock()

	before := wire.Len()
	cs.masqueMaybeRearmDownloadReceiveWindow(64)
	if wire.Len() <= before {
		t.Fatal("expected low-water rearm WINDOW_UPDATE")
	}
}

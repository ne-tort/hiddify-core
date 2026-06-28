//go:build with_gvisor && linux

package tun

import "testing"

func TestHostEgressPrefetchPopPush(t *testing.T) {
	p := &hostEgressPrefetch{}
	p.push([]byte{1, 2, 3})
	dst := make([]byte, 8)
	n, ok := p.pop(dst)
	if !ok || n != 3 {
		t.Fatalf("pop=%d ok=%v want 3 true", n, ok)
	}
	if _, ok := p.pop(dst); ok {
		t.Fatal("second pop want empty")
	}
}

func TestHostEgressPrefetchMaxCap(t *testing.T) {
	p := &hostEgressPrefetch{}
	for i := 0; i < hostEgressPrefetchMax+8; i++ {
		p.push([]byte{byte(i)})
	}
	p.mu.Lock()
	qlen := len(p.q)
	p.mu.Unlock()
	if qlen != hostEgressPrefetchMax {
		t.Fatalf("queue len=%d want cap %d", qlen, hostEgressPrefetchMax)
	}
}

func TestHostEgressPrefetchBatchDrain(t *testing.T) {
	p := &hostEgressPrefetch{}
	const n = 32
	for i := 0; i < n; i++ {
		p.push([]byte{byte(i), byte(i >> 8)})
	}
	buf := make([]byte, 8)
	got := 0
	for {
		if _, ok := p.pop(buf); !ok {
			break
		}
		got++
	}
	if got != n {
		t.Fatalf("drained=%d want %d", got, n)
	}
}

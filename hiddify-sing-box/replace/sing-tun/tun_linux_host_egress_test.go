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

func TestParseVirtioEgressFrameIPv6AfterZeroHdr(t *testing.T) {
	ip6 := make([]byte, 40)
	ip6[0] = 0x60
	raw := make([]byte, virtioNetHdrLen+len(ip6))
	copy(raw[virtioNetHdrLen:], ip6)
	dst := make([]byte, 128)
	n, err := parseVirtioEgressFrame(raw, dst)
	if err != nil || n != len(ip6) {
		t.Fatalf("parse n=%d err=%v want %d nil", n, err, len(ip6))
	}
	if dst[0]>>4 != 6 {
		t.Fatalf("dst[0]=%#x want IPv6 version 6", dst[0])
	}
}

func TestParseVirtioEgressFrameSalvage(t *testing.T) {
	// Minimal IPv4 header (20 B) after zero virtio hdr (handshake-sized egress).
	ip := make([]byte, 20)
	ip[0] = 0x45
	raw := make([]byte, virtioNetHdrLen+len(ip))
	copy(raw[virtioNetHdrLen:], ip)
	dst := make([]byte, 128)
	n, err := parseVirtioEgressFrame(raw, dst)
	if err != nil || n != 20 {
		t.Fatalf("parse n=%d err=%v want 20 nil", n, err)
	}
	if dst[0] != 0x45 {
		t.Fatalf("dst[0]=%#x want 0x45", dst[0])
	}
	// Plain IP without virtio prefix (mis-sync salvage @ offset 0).
	raw2 := append([]byte(nil), ip...)
	n, err = parseVirtioEgressFrame(raw2, dst)
	if err != nil || n != 20 {
		t.Fatalf("plain n=%d err=%v want 20 nil", n, err)
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

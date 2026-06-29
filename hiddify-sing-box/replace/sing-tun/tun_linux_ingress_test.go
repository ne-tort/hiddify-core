//go:build linux

package tun

import "testing"

func TestWriteIngressVirtioHdrEncode(t *testing.T) {
	p := make([]byte, 64)
	for i := range p {
		p[i] = byte(i)
	}
	hdr := make([]byte, virtioNetHdrLen)
	if err := (virtioNetHdr{}).encode(hdr); err != nil {
		t.Fatal(err)
	}
	for _, b := range hdr {
		if b != 0 {
			t.Fatalf("default virtio hdr byte=%d want 0", b)
		}
	}
}
